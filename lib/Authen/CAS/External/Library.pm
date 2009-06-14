package Authen::CAS::External::Library;

use 5.008001;
use strict;
use utf8;
use version 0.74;
use warnings 'all';

# Module metadata
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.01';

use MooseX::Types 0.08 -declare => [qw(
	ServiceTicket
	TicketGrantingCookie
)];

# Import built-in types
use MooseX::Types::Moose qw(Int Str);

# Type definitions
subtype ServiceTicket,
	as Str,
	where { m{\A ST-.{1,256}}msx };

subtype TicketGrantingCookie,
	as Str,
	where { m{\A [A-Za-z0-9-]+ \z}msx };

1;

__END__

=encoding utf8

=head1 NAME

Authen::CAS::External::Library - Types library

=head1 VERSION

This documentation refers to L<Authen::CAS::External::Library> version 0.01

=head1 SYNOPSIS

  use Authen::CAS::External::Library qw(ServiceTicket);
  # This will import ServiceTicket type into your namespace as well as some
  # helpers like to_ServiceTicket and is_ServiceTicket. See MooseX::Types
  # for more information.

=head1 DESCRIPTION

This module provides types for Authen::CAS::External

=head1 METHODS

No methods.

=head1 TYPES PROVIDED

=over 4

=item * ServiceTicket

Provides no coersons.

=item * TicketGrantingCookie

Provides no coersons.

=back

=head1 DEPENDENCIES

This module is dependent on the following modules:

=over 4

=item * L<MooseX::Types> 0.08

=back

=head1 AUTHOR

Douglas Christopher Wilson, C<< <doug at somethingdoug.com> >>

=head1 BUGS AND LIMITATIONS

Please report any bugs or feature requests to
C<bug-authen-cas-external at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Authen-CAS-External>. I will
be notified, and then you'll automatically be notified of progress on your bug
as I make changes.
 
=head1 LICENSE AND COPYRIGHT

Copyright 2009 Douglas Christopher Wilson, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
 
