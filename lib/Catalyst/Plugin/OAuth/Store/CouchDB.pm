package Catalyst::Plugin::OAuth::Store::CouchDB;

use strict;
use warnings;
use base qw/Catalyst::Plugin::OAuth/;
use Store::CouchDB;

sub get_request_token_secret {
    my ( $self, $token_string ) = @_;
    my $db = $self->_db();

    my $view = {
        view => 'oauth/get_request_token',
        opts => { key => '"' . $token_string . '"' },
    };
    my $doc   = $db->get_view($view);
    my $token = $doc->{$token_string};

    unless ( $token
        && $token->{is_authorized_by_user}
        && !$token->{is_exchanged_to_access_token}
        && !$token->{is_expired} )
    {
        return $self->error(q{Invalid token});
    }
    return $token->{secret};
}

sub publish_authorize_pin {
    my ( $self, $token_string, $user ) = @_;
    my $db = $self->_db();

    my $view = {
        view => 'oauth/get_request_token',
        opts => { key => '"' . $token_string . '"' },
    };
    my $doc   = $db->get_view($view);
    my $token = $doc->{$token_string};

    unless ( $token
        && !$token->{is_exchanged_to_access_token}
        && !$token->{is_expired} )
    {
        return $self->error(q{Invalid token});
    }

    $token->{is_authorized_by_user} = 1;
    $token->{user} = $user;
    my $pin = int(rand(99999999));
    $token->{verifier} = $pin;
    $token->{has_verifier} = 1;
    $db->put_doc({doc => $token});

    return $pin;
}

sub get_access_token_secret {
    my ( $self, $token_string ) = @_;
    my $db = $self->_db();

    my $view = {
        view => 'oauth/get_access_token',
        opts => { key => '"' . $token_string . '"' },
    };
    my $doc   = $db->get_view($view);
    my $token = $doc->{$token_string};
    unless ( $token
        && !$token->{is_expired} )
    {
        return $self->error(q{Invalid token});
    }
    return $token->{secret};
}

sub get_access_token_author {
    my ( $self, $token_string ) = @_;
    my $db = $self->_db();

    my $view = {
        view => 'oauth/get_access_token',
        opts => { key => '"' . $token_string . '"' },
    };
    my $doc   = $db->get_view($view);
    my $token = $doc->{$token_string};
    unless ( $token
        && !$token->{is_expired} )
    {
        return $self->error(q{Invalid token});
    }
    return $token->{author};
}

sub get_consumer_secret {
    my ( $self, $consumer_key ) = @_;
    my $db = $self->_db();

    my $view = {
        view => 'oauth/get_consumer_token',
        opts => { key => '"' . $consumer_key . '"' },
    };
    my $doc      = $db->get_view($view);
    my $consumer = $doc->{$consumer_key};
    unless ( $consumer
        && $consumer->{is_valid} )
    {
        return $self->error(q{Inalid consumer_key});
    }
    return $consumer->{secret};
}

sub publish_request_token {
    my ( $self, $consumer_key, $callback_url ) = @_;
    my $db    = $self->_db();
    my $token = OAuth::Lite::Token->new_random;
    my $doc   = {
        token        => $token->token,
        secret       => $token->secret,
        realm        => $self->oauth_realm,
        consumer_key => $consumer_key,
        expired_on   => '',
        callback     => $callback_url,
        type => 'request',
    };
    my $id = $db->put_doc( { doc => $doc } );
    return $token;
}

sub publish_access_token {
    my ( $self, $consumer_key, $request_token_string, $verifier ) = @_;
    my $db   = $self->_db();
    my $view = {
        view => 'oauth/get_request_token',
        opts => { key => '"' . $request_token_string . '"' },
    };
    my $doc           = $db->get_view($view);
    my $request_token = $doc->{$request_token_string};
    unless ( $request_token
        && $request_token->{is_authorized_by_user}
        && !$request_token->{is_exchanged_to_access_token}
        && !$request_token->{is_expired}
        && $request_token->{has_verifier}
        && $request_token->{verifier} eq $verifier )
    {
        return $self->error(q{Invalid token});
    }
    my $access_token = OAuth::Lite::Token->new_random;
    $doc          = {
        token        => $access_token->{token},
        realm        => $self->oauth_realm,
        secret       => $access_token->{secret},
        consumer_key => $consumer_key,
        author       => $request_token->{user},
        expired_on   => '',
        type => 'access',
    };

    my $id = $db->put_doc( { doc => $doc } );
    $request_token->{is_exchanged_to_access_token} = 1;
    $db->put_doc( { id => $request_token->{_id}, doc => $request_token } );

    return $access_token;
}

sub check_nonce_and_timestamp {
    my ( $self, $consumer_key, $nonce, $timestamp ) = @_;
    my $db   = $self->_db();
    my $view = {
        view => 'oauth/check_nonce_and_timestamp',
        opts => { key => '["' . $nonce . '","' . $timestamp . '"]' },
    };
    my $count = $db->get_array_view($view);

    #my $request_token = $doc->{$request_token_string};
    #my $request_log = MyDB::Scheme->resultset('RequestLog');

    # check against replay-attack
    # TODO has to go into CouchDB view and implement rate limit here
    #my $count = $request_log->count(
    #    {
    #        consumer_key => $consumer_key,
    #        -nest        => [
    #            nonce     => $nonce,
    #            timestamp => { '>' => $timestamp },
    #        ],
    #    }
    #);
    my $c = $count->[0] || 0;
    if ( $c > 0 ) {
        return $self->error(q{Invalid timestamp or consumer});
    }

    # save new request log.
    my $doc = {
        consumer_key => $consumer_key,
        nonce        => $nonce,
        timestamp    => $timestamp,
        type => 'log',
    };
    $db->put_doc( { doc => $doc } );
    return 1;
}

sub _db {
    my $self = shift;
    my $db   = Store::CouchDB->new();
    $db->host( $self->config->{OAuth}->{store}->{host} );
    $db->db( $self->config->{OAuth}->{store}->{db} );
    return $db;
}

1;
