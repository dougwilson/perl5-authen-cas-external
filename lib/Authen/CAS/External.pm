package Authen::CAS::External;

use 5.008001;
use strict;
use utf8;
use version 0.74;
use warnings 'all';

# Module metadata
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.01';

use Authen::CAS::External::Library qw(TicketGrantingCookie);
use Moose 0.77;
use MooseX::StrictConstructor 0.08;
use MooseX::Types::Moose qw(Str);
use URI 1.22;

# Role

with 'Authen::CAS::External::UserAgent';

# Attributes

has cas_url => (
	is       => 'rw',
	isa      => 'String',
	required => 1,
	documentation => q{The URL of the CAS site. This does not include /login},
);
has password => (
	is  => 'rw',
	isa => Str,

	clearer   => 'clear_password',
	predicate => 'has_password',
	trigger   => sub { shift->clear_ticket_granting_cookie },
);
has ticket_granting_cookie => (
	is  => 'rw',
	isa => TicketGrantingCookie,

	clearer       => 'clear_ticket_granting_cookie',
	documentation => q{The Ticket Granting Cookie for the CAS user session},
	predicate     => 'has_ticket_granting_cookie',
);
has username => (
	is  => 'rw',
	isa => Str,

	clearer   => 'clear_username',
	predicate => 'has_username',
	trigger   => sub { shift->clear_ticket_granting_cookie },
);

# Methods

sub authenticate {
	my ($self, %args) = @_;

	# Splice out the variables
	my ($service, $gateway, $renew) = @args{qw(service gateway renew)};

	# Get the URI to request
	my $url = $self->service_request_url(
		(defined $gateway ? (gateway => $gateway) : () ),
		(defined $renew   ? (renew   => $renew  ) : () ),
		(defined $service ? (service => $service) : () ),
	);

	# Do not redirect back to service
	my $redirect_back = $self->redirect_back;
	$self->redirect_back(0);

	# Get the service
	my $response = $self->get($url);

	# Restore previous value
	$self->redirect_back($redirect_back);

	if (!$self->has_previous_response) {
		confess 'Failed retrieving response';
	}

	# Set our ticket granting ticket if we have one
	if ($self->previous_response->has_ticket_granting_cookie) {
		$self->ticket_granting_cookie($self->previous_response->ticket_granting_cookie);
	}

	# Return the last response
	return $self->previous_response;
}

sub get_cas_credentials {
	my ($self, %args) = @_;

	# Splice out the variables
	my ($service) = @args{qw(service)};

	# This default callback stub simply returns the stored
	# credentials
	if (!$self->has_username) {
		confess 'Unable to authenticate because no username was provided';
	}

	if (!$self->has_password) {
		confess 'Unable to authenticate because no password was provided';
	}

	# Return username, password
	return $self->username, $self->password;
}

sub get_cas_ticket_granting_cookie {
	my ($self, %args) = @_;

	# Splice out the variables
	my ($username, $service) = @args{qw(username service)};

	# This default callback stub simply returns the stored
	# credentials
	if (!$self->has_ticket_granting_cookie) {
		return;
	}

	# Return ticket granting ticket
	return $self->ticket_granting_cookie;
}

# Make immutable
__PACKAGE__->meta->make_immutable;

# Clean out Moose keywords
no Moose;

1;

__END__

=head1 NAME

Authen::CAS::External - Authenticate with CAS servers as a browser
would.

=head1 VERSION

This documentation refers to <Authen::CAS::External> version 0.01

=head1 SYNOPSIS

  my $cas_auth = Authen::CAS::External->new(
      cas_url => 'https://cas.mydomain.com/',
  );

  # Set the username and password
  $cas_auth->username('joe_smith');
  $cas_auth->password('hAkaT5eR');

  my $response = $cas_auth->authentiate();

  my $secured_page = $ua->get($response->destination);

=head1 DESCRIPTION

Provides a way to authenticate with a CAS server just as a browser
would. This is useful with web scrapers needing to login to a CAS
site.

=head1 METHODS

=head2 authenticate

This method will authenticate against the CAS service using the presupplied
username and password and will return a L<Authen::CAS::External::Response>
object.

=head1 DEPENDENCIES

=over 4

=item * L<Moose> 0.77

=item * L<MooseX::StrictConstructor> 0.08

=item * L<MooseX::Types::Moose>

=item * L<URI> 1.22

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


