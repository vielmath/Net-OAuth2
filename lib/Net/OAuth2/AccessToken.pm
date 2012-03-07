package Net::OAuth2::AccessToken;
use warnings;
use strict;
use base qw(Class::Accessor::Fast);
use JSON;
use Carp;
use URI::Escape;
__PACKAGE__->mk_accessors(qw/client refresh_token expires_in expires_at scope token_type site auto_refresh /);

sub new {
	my $class = shift;
	my %opts = @_;
	my $self = bless \%opts, $class;
	if( defined $self->{expires_at} ) {
		$self->refresh() if $self->expired;
	} elsif( defined $self->{expires_in} and $self->{expires_in} =~ /^\d+$/) {
		$self->expires_at(time() + $self->{expires_in});
	} else {
		delete $self->{expires_in};
	}
	return $self;
}

# True if the token in question has an expiration time.
sub expires {
	my $self = shift;
	return defined $self->expires_at;
}

sub expired {
	my $self  = shift;
	my $delay = shift || 0;
	return defined $self->expires_at && $self->expires_at <= $delay+time;
}

sub refresh {
	my $self = shift;
	if( defined $self->refresh_token ) {
		if( !defined $self->expires_at() || $self->expired(60) ) {
			my $head = HTTP::Headers->new( Content_Type => 'application/x-www-form-urlencoded' );
			my $body = join('&',(
				'client_id='.$self->client->id,
				'client_secret='.$self->client->secret,
				'refresh_token='.$self->refresh_token,
				'grant_type=refresh_token',
			));
			my $req = HTTP::Request->new( POST => $self->client->access_token_url, $head, $body );
			my $ans = $self->client->user_agent->request( $req );
			$ans->is_success() or croak 'Could not refresh access token: '.$ans->code.' / '.$ans->title;
			my $dta = eval{local $SIG{__DIE__}; decode_json($ans->decoded_content)} || {};
			$dta->{access_token} or croak "no access token found in refresh data...\n".$ans->decoded_content;
			$self->{access_token} = $dta->{access_token};
			$dta->{expires_in} or croak "no expiration found in refresh data...\n".$ans->decoded_content;
			$self->expires_in( $dta->{expires_in} );
			$self->expires_at( time() + $dta->{expires_in} );
			$self->token_type( $dta->{token_type} ) if $dta->{token_type};
		}
	} else {
		croak 'unable to refresh access_token without refresh_token';
	}
	return $self->{access_token};
}

sub access_token {
	my $self = shift;
	$self->refresh() if $self->expired && $self->auto_refresh;
	return $self->{access_token};
}

sub request {
	my $self = shift;
	my ($method, $uri, $header, $content) = @_;

	my $request = HTTP::Request->new(
		$method => $self->site_url($uri), $header, $content
	);
	# We assume a bearer token type, but could extend to other types in the future
	my $bearer_token_scheme = $self->client->bearer_token_scheme;
	my @bearer_token_scheme = split ':', $bearer_token_scheme;
	if (lc($bearer_token_scheme[0]) eq 'auth-header') {
		# Specs suggest using Bearer or OAuth2 for this value, but OAuth appears to be the de facto accepted value.
		# Going to use OAuth until there is wide acceptance of something else.
		my $auth_scheme = $bearer_token_scheme[1] || 'OAuth';
		$request->headers->push_header(Authorization => $auth_scheme.' '.$self->access_token);
	} elsif (lc($bearer_token_scheme[0]) eq 'uri-query') {
		my $query_param = $bearer_token_scheme[1] || 'oauth_token';
		$request->uri->query_form($request->uri->query_form, $query_param => $self->access_token);
	} elsif (lc($bearer_token_scheme[0]) eq 'form-body') {
		croak "Embedding access token in request body is only valid for 'application/x-www-form-urlencoded' content type"
		unless $request->headers->content_type eq 'application/x-www-form-urlencoded';
		my $query_param = $bearer_token_scheme[1] || 'oauth_token';
		$request->add_content(
			((defined $request->content and length $request->content) ?  '&' : '') .  
			uri_escape($query_param).'='.uri_escape($self->access_token)
		);
	}
	my $r = $self->client->request($request);
	die( $r->status_line()."\n".$r->decoded_content()."\n" ) unless $r->is_success;
	return $r;
}

sub get {
	return shift->request('GET', @_);
}

sub get_json {
	#Accept => 'application/json; charset=utf-8' ?
	return decode_json( shift->get( @_ )->decoded_content )
}

sub post {
	return shift->request('POST', @_);
}

sub delete {
	return shift->request('DELETE', @_);
}

sub put {
	return shift->request('PUT', @_);
}

sub save {
	my $self = shift;
	my %hash;
	for (qw/access_token token_type refresh_token expires_at scope error error_desription error_uri state site auto_refresh/) {
		$hash{$_} = $self->{$_} if defined $self->{$_};
	}
	return %hash;
}

sub to_string {
	return encode_json({ shift->save });
}

=head2 site_url

Returns url based on base held in site paramater - otherwise delegates to 
the client

=cut

sub site_url {
	my $self = shift;
	my $path = shift;
	my %params = @_;
	my $url;
	
	if (defined $self->{site}) {
		$url = URI->new_abs($path, $self->{site});
		if (@_) {
			$url->query_form($url->query_form , %params);
		}
	}
	else {
		$url = $self->client->site_url( $path, %params );
	}

	return $url;
}

=head1 NAME

Net::OAuth2::AccessToken - OAuth Access Token

=head1 SEE ALSO

L<Net::OAuth>

=head1 LICENSE AND COPYRIGHT

Copyright 2010 Keith Grennan.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut


1;
