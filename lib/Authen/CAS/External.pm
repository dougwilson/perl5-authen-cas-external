package Authen::CAS::External;

use 5.008;
use strict;
use utf8;
use version 0.74;
use warnings 'all';

# Module metadata
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.01_01';

use Carp qw(croak);
use Moose 0.74;
use Authen::CAS::Client 0.03;
use WWW::Mechanize 1.54;

# Attributes

has 'cas_url' => (
	is       => 'rw',
	isa      => 'String',
	required => 1,
	documentation => q{The URL of the CAS site. This does not include /login},
);

has 'service_url' => (
	is  => 'rw',
	isa => 'String',
	documentation => q{The service URL the user is trying to authenticate for},
);

has 'ticket_granting_cookie' => (
	is => 'rw',
	isa => 'String',
	documentation => q{The Ticket Granting Cookie for the CAS user session},
);

sub get_service_ticket {
	my ($self, $service, $username, $password) = @_;

	if (!defined $service) {
		# The service URL must be provided
		croak 'A service URL MUST be provided to get a service ticket.';
	}

	croak 'TODO: Implement get_service_ticket';
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

Version 0.01_01

=head1 SYNOPSIS

Provides a way to authenticate with a CAS server just as a browser
would. This is useful with web scrapers needing to login to a CAS
site.

=head1 METHODS

=head2 get_service_ticket

B<get_service_ticket($service, $username, $password)>

This method will get the service ticket from the CAS server for the
specified service and using the supplied username and password.

=head1 DEPENDENCIES

=over 4

=item * L<Moose> 0.74

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


