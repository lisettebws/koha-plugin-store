package KohaPluginStore::Controller::GitHubOAuth;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use KohaPluginStore::Model::Plugin;
use JSON;

# Is user authenticated?
sub github_logged_in {
    my $self = shift;
    return defined $self->session('github_access_token');
}

# Get current user info (cached in session)
sub current_github_user {
    my $self = shift;
    return $self->stash('current_github_user') if $self->stash('current_github_user');
    
    my $oauth = $self->app->github_oauth;
    my $token = $self->session('github_access_token')
        or return undef;
    
    my $user = $oauth->get_user($token);
    $self->stash(current_github_user => $user);
    
    return $user;
}

# Require authentication
sub require_github_auth {
    my $self = shift;
    
    unless ($self->github_logged_in) {
        $self->flash(error => 'You must be logged in to access this page');
        $self->redirect_to('auth');
        return 0;
    }
    return 1;
}

1;