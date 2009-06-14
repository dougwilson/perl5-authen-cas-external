package Authen::CAS::External::Response;

use 5.008001;
use strict;
use utf8;
use version 0.74;
use warnings 'all';

# Module metadata
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.01';

use Authen::CAS::External::Library qw(ServiceTicket TicketGrantingCookie);
use LWP::UserAgent 5.819;
use Moose 0.77;
use MooseX::StrictConstructor 0.08;
use MooseX::Types::Moose qw(Str);
use URI 1.22;

# Attributes

has destination => (
	is  => 'ro',
	isa => 'URI',

	clearer   => '_clear_destination',
	predicate => 'has_destination',
);
has response => (
	is  => 'ro',
	isa => 'HTTP::Response',

	clearer   => '_clear_response',
	predicate => 'has_response',
);
has service => (
	is  => 'ro',
	isa => 'URI',

	clearer   => '_clear_service',
	predicate => 'has_service',
);
has service_ticket => (
	is  => 'ro',
	isa => ServiceTicket,

	clearer   => '_clear_service_ticket',
	predicate => 'has_service_ticket',
);
has ticket_granting_cookie => (
	is  => 'ro',
	isa => TicketGrantingCookie,

	clearer   => '_clear_ticket_granting_cookie',
	predicate => 'has_ticket_granting_cookie',
);

# Methods

sub get_cookies {
	my ($self, @cookie_names) = @_;

	if (!$self->is_success) {
		confess 'Unable to retrieve cookies from a failed response';
	}

	if (!$self->has_destination) {
		confess 'Unable to retrieve cookies without a destination';
	}

	# Create a new user agent to use
	my $user_agent = LWP::UserAgent->new(
		cookie_jar    => {},
		max_redirects => 0,
	);

	# Make a HEAD request
	my $response = $user_agent->head($self->destination);

	if (@cookie_names == 0) {
		# Return the cookies a a string
		return $user_agent->cookie_jar->as_string;
	}

	# Cookies to return
	my %cookies;

	# Find the cookies
	$user_agent->cookie_jar->scan(sub {
		my (undef, $key, $value, undef, $domain) = @_;

		if ($domain eq $self->destination->host) {
			# Go through each cookie name
			foreach my $cookie_name (@cookie_names) {
				if ($cookie_name eq $key) {
					# Set the cookie for return
					$cookies{$cookie_name} = $value;
				}
			}
		}
	});

	# Return the found cookies as a hash
	return %cookies;
}

sub is_success {
	my ($self) = @_;

	# If there is a ticket granting ticket, the login
	# was successful
	return $self->has_ticket_granting_cookie;
}

#
# PRIVATE METHODS
#

sub BUILD {
	my ($self) = @_;

	if (!$self->has_destination
		&& $self->has_service
		&& $self->has_service_ticket) {
		# The destination is the service with the sertice ticket
		# as "ticket" in the query parameters
		$self->destination($self->service->query_param('ticket', $self->service_ticket));
	}

	return;
}

# Make immutable
__PACKAGE__->meta->make_immutable;

# Clean out Moose keywords
no Moose;

1;

__END__

=head1 NAME

Authen::CAS::External::Response - Response from CAS interaction.

=head1 VERSION

This documentation refers to L<Authen::CAS::External::Response> version 0.01

=head1 SYNOPSIS

  my $response = $cas_external->authenticate;

  if (!$response->is_success) {
    croak 'Authentication failed';
  }

  # Get a PHP Session cookie
  my %cookies = $response->get_cookies('PHPSESSID');
  my $PHP_SESSION_ID = $cookies{PHPSESSID};

  # Continue the request
  $response = $ua->get($response->destination);

=head1 DESCRIPTION

This module is rarely created by anything other than
L<Authen::CAS::External::UserAgent>. This is an object that is provided to
make determining what the CAS response was easier.

=head1 METHODS

=head2 get_cookies

This method is for convience pruposes. Using this method, a HEAD request
will be made to the destination URL and will return a hash of the cookie
names and their values that would have been set.

B<get_cookies()>

When no arguments are provided, returns a string of the cookies, using the
as_string method of L<HTTP::Cookie>.

B<get_cookies(qw(PHPSESSID))>

When given a list of cookie names, a hash is returned with only those cookies
where the cookie name is the key and the value is the value.

=head2 is_success

Returns a Boolean of weither or not this response indicates a successful
authentication.

=head1 DEPENDENCIES

=over 4

=item * L<Moose> 0.74

=item * L<MooseX::StrictConstructor> 0.08

=item * L<Authen::CAS::Client> 0.03

=item * L<WWW::Mechanize> 1.54

=back

=head1 AUTHOR

Douglas Christopher Wilson, C<< <doug at somethingdoug.com> >>

=head1 BUGS AND LIMITATIONS

Please report any bugs or feature requests to C<bug-authen-cas-external at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Authen-CAS-External>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Authen::CAS::External


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Authen-CAS-External>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Authen-CAS-External>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Authen-CAS-External>

=item * Search CPAN

L<http://search.cpan.org/dist/Authen-CAS-External/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2009 Douglas Christopher Wilson, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


