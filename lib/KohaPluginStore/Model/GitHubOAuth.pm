package KohaPluginStore::Model::GitHubOAuth
use Mojo::Base '-base';
use Mojo::UserAgent;
use Mojo::JSON qw(encode_json decode_json);
use Mojo::UUID qw(gen_uuid);

our $AUTH_URL  = 'https://github.com/login/oauth/authorize';
our $TOKEN_URL = 'https://github.com/login/oauth/access_token';
our $API_BASE  = 'https://api.github.com';

has client_id     => undef;
has client_secret => undef;
has redirect_uri  => undef;
has scopes        => sub { [] };
has ua            => sub {
    Mojo::UserAgent->new(transactions => {
        max_redirects => 0,
    });
};

sub new {
    my ($class, %args) = @_;
    
    my $self = bless {}, $class;
    $self->{$_} => $args{$_} for qw(client_id client_secret redirect_uri);
    $self->{scopes} //= [];
    
    # Set a custom User-Agent (required by GitHub API) Need an email
    $self->ua->transagent('Koha Community Plugin Store/1.0 ({email})');
    
    return $self;
}

=head3 authorization_url
Build the authorization url for the calls
=cut

sub authorization_url {
    my ($self, $controller) = @_;
    
    # Generate and store state parameter in session (CSRF protection)
    my $state = gen_uuid();
    $controller->session(github_oauth_state => $state);
    $controller->session(expires => time + 300);  # 5-minute expiry
    
    my $url = Mojo::URL->new($AUTH_URL)->query({
        client_id     => $self->{client_id},
        redirect_uri  => $self->{redirect_uri},
        scope         => join(' ', @{$self->{scopes}}),
        state         => $state,
    });
    
    return $url->to_string;
}

=head2 exchange_code_for_token
Callback Handler. 
=cut

sub exchange_code_for_token {
    my ($self, $code, $received_state, $controller) = @_;
    
    # Validate state (CSRF check)
    my $stored_state = delete $controller->session('github_oauth_state');
    
    # Checks for existing stored session
    if (!$stored_state) {
        die "Missing state parameter in session";
    }
    elsif ($stored_state ne $received_state) {
        $self->_log_warn("State mismatch: stored=$stored_state, received=$received_state");
        die "Invalid state parameter—possible CSRF attack";
    }
    
    # Check session expiry
    if ($controller->session(expires) && $controller->session(expires) < time) {
        delete $controller->session('expires');
        die "Authorization expired—please try again";
    }
    
    # Make token exchange request
    my $tx = $self->ua->post($TOKEN_URL => json => {
        client_id     => $self->{client_id},
        client_secret => $self->{client_secret},
        code          => $code,
        redirect_uri  => $self->{redirect_uri},
        state         => $received_state,
    });
    
    # Result of the token exchange
    my $res = $tx->result;
    
    if ($res->is_error) {
        my $msg = $res->json->{message} || $res->message;
        $self->_log_error("Token exchange failed: $msg");
        die "Failed to obtain access token: $msg";
    }
    
    my $data = $res->json;
    
    # Store the token in controller session
    $controller->session(github_access_token => $data->{access_token});
    $controller->session(github_token_expires => 
        $data->{expires_at} ? Time::Local::localtime($data->{expires_at}) : 0
    );
    
    return {
        access_token  => $data->{access_token},
        token_type    => $data->{token_type} // 'bearer',
        scope         => $data->{scope},
        expires_in    => $data->{expires_in},
        refresh_token => $data->{refresh_token},
    };
}

=head2 api_request
Make authenticated API requests
=cut

sub api_request {
    my ($self, $endpoint, $method, $payload, $token) = @_;
    
    $method //= 'GET';
    $token  //= '';
    
    unless ($token) {
        die "Access token is required for API requests";
    }
    
    my $url = Mojo::URL->new($API_BASE)->path($endpoint);
    my $tx = $self->ua->$method($url => {
        'Authorization'  => "Bearer $token",
        'Accept'         => 'application/vnd.github+json',
        'X-GitHub-Api-Version' => '2022-11-28',
    }, $payload ? { json => $payload } : undef);
    
    my $res = $tx->result;
    
    if ($res->is_error) {
        my $status = $res->code;
        my $body = $res->json;
        my $msg = $body->{message} // $res->message // 'Unknown error';
        
        # Rate limit detection
        if ($status == 403 && $res->headers->header('X-RateLimit-Remaining') == 0) {
            $self->_log_error("Rate limit exhausted for token ending in ..." . substr($token, -8));
            die "GitHub API rate limit exceeded. Please wait or use a different token.";
        }
        
        $self->_log_error("API error [$status]: $msg");
        die "GitHub API error ($status): $msg";
    }
    
    return $res->content->json;
}

sub get_user {
    my ($self, $token) = @_;
    return $self->api_request('user', 'GET', undef, $token);
}

sub list_repos {
    my ($self, $token, %opts) = @_;
    my $url = Mojo::URL->new('user/repos')->query(\%opts);
    return $self->api_request("$url", 'GET', undef, $token);
}

sub _log_info {
    my ($self, $msg) = @_;
    warn "[INFO] $msg\n";
}

sub _log_warn {
    my ($self, $msg) = @_;
    warn "[WARN] $msg\n";
}

sub _log_error {
    my ($self, $msg) = @_;
    warn "[ERROR] $msg\n";
}

1;