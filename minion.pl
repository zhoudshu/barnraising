#! /usr/bin/perl -w
#
# barnraising - system for sharing bandwidth with overloaded Web servers
# barnraising-minion - provides services on behalf of another server
#
# Copyright 2003 Christopher Lesniewski-Laas
# $Id: minion.pl,v 1.11 2003/08/07 13:32:19 ctl Exp $
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#


my $VERSION = "0.1.0";


use strict;

use Getopt::Long;
use Pod::Usage;
use Error;
$Error::Debug = $ENV{ERROR_DEBUG};

use Barnraising::Resource;
use Barnraising::Service;
use Barnraising::Expander::Cache;



GetOptions(
	   "version"     => \my $opt_version,
	   "help"        => \my $opt_help,
	  )
  or pod2usage(2);
$opt_help and pod2usage(1);
$opt_version and do {
  STDOUT->print( "barnraising-minion $VERSION\n" );
  exit 0;
};

my $resource_uri = shift
  or pod2usage(2);




# Automatically reap children.
# Note that this breaks the system() and wait() return values.
$SIG{CHLD} = "IGNORE";

#zhoudshu added for one bug
my @service_names = ('ImpTLS', 'Cache');

my $resource = Barnraising::Resource->new( $resource_uri );
my @services = map { Barnraising::Service->from_tag( $_ ) } @service_names;
my @daemons = $resource->offer( Services => \@services );
for my $daemon (@daemons) { $daemon->wait(); }




__END__

=head1 NAME

barnraising-minion

=head1 SYNOPSIS

barnraising-minion [options] <URI> [service-list]

=head1 OPTIONS

=over 8

=back

=head1 DESCRIPTION

B<minion.pl> is a minion.

=cut
