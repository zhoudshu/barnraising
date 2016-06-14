#! /usr/bin/perl -w
#
# barnraising - system for sharing bandwidth with overloaded Web servers
# barnraising-broker - configuration daemon for barnraising minions
#
# Copyright 2003 Christopher Lesniewski-Laas
# $Id: broker.pl,v 1.18 2003/07/15 19:40:49 ctl Exp $
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


use strict;

use Barnraising::Broker::Database;
use Barnraising::Broker::Server;

use Getopt::Long;
use Pod::Usage;
use IO::Socket;
use Error qw( :try );
$Error::Debug = $ENV{ERROR_DEBUG};



# Process options.
my $opt_broker_port = 777;

#zhoudshu add self database infomation
my ($opt_mysql_connect, $opt_mysql_username, $opt_mysql_password)
#= ("localhost", "mydns", "mydns");
  = ("10.10.100.21", "root", "xiao12");
my ($opt_mydns_pid, $opt_reset, @opt_create_zone, @opt_add_primary, $opt_help);
GetOptions(
	   "mysql-connect=s"  => \$opt_mysql_connect,
	   "mysql-username=s" => \$opt_mysql_username,
	   "mysql-password=s" => \$opt_mysql_password,
	   "mydns-pid=i"      => \$opt_mydns_pid,
	   "broker-port=s"    => \$opt_broker_port,
	   "reset"            => \$opt_reset,
	   "create-zone=s"    => \@opt_create_zone,
	   "add-primary=s"    => \@opt_add_primary,
	   "help|?"           => \$opt_help,
	  )
  or pod2usage(2);
$opt_help and pod2usage(1);





sub open_database {
  DBI->connect( "DBI:mysql:database=mydns;host=$opt_mysql_connect",
		$opt_mysql_username, $opt_mysql_password,
		{
		 AutoCommit => 0,
		 HandleError => sub {
		   local $Error::Depth = $Error::Depth + 1;
		   throw Error::Simple $_[0];
		 },
		} )
    or throw Error::Simple "DBI->connect: $DBI::errstr";
}




# Check for the --reset or --create-zone commands.
if ($opt_reset || @opt_create_zone || @opt_add_primary) {
  my $dbh = open_database();
  my $mydns = Barnraising::Broker::Database->new( DBI => $dbh )->mydns;

  if ($opt_reset) {
    $mydns->reset();
    STDOUT->print( "MyDNS database successfully initialized.\n" );
  }

  for my $zone (@opt_create_zone) {
    $mydns->create_zone( $zone );
    STDOUT->print( "Zone $zone successfully created.\n" );
  }

  for my $ap (@opt_add_primary) {
    $ap =~ /^(.*):(.*)$/ or throw Error::Simple "bad syntax: $ap";
    my ($zone_name, $host) = ($1, $2);
    my $zone = $mydns->lookup_zone( $zone_name );
    my $impd_name = "impd";
    if ($host =~ /^\d+\.\d+\.\d+\.\d+$/) {
      $zone->create_rr( "A",     $impd_name, $host );
    } else {
      $host =~ s/\.?$/./;
      $zone->create_rr( "CNAME", $impd_name, $host );
    }
    STDOUT->print( "Hostname $impd_name.$zone_name bound to $host.\n" );
  }

  $dbh->disconnect();
  exit 0;
}
# Else, start up the broker normally.



# Set up a child reaper.
$SIG{CHLD} = sub { wait; };


# Create the listening socket.
my $listen_socket = IO::Socket->new( Domain => AF_INET,
				     Type   => SOCK_STREAM,
				     Proto  => "tcp",
				     Listen => 5,
				     LocalPort => $opt_broker_port )
  or throw Error::Simple "IO::Socket->new (listen): $@";

my $broker_port = $listen_socket->sockport();
STDOUT->printflush( "Listening on $broker_port...\n" );

# Main accept-fork-handle loop.
while (1) {

      #zhoudshu add sleep for exit exception
      STDOUT->printflush( "before accept ...\n" );
      sleep(5);
  my $accept_socket = $listen_socket->accept()
    or throw Error::Simple "IO::Socket->accept: $@ ($!)";

      STDOUT->printflush( "after accept ...\n" );
  defined( my $kid = fork() ) or throw Error::Simple "fork: $!";
  if ($kid) {
    # In parent, close the accepted socket to decrease refcount.
    $accept_socket->close();
  } else {
    # In child, handle the connection.
    try {

      STDOUT->printflush( "open database ...\n" );
      my $dbh = open_database();
      my $db = Barnraising::Broker::Database->new( DBI       => $dbh,
						MyDNS_PID => $opt_mydns_pid );
      STDOUT->printflush( "server new ...\n" );
      my $server = Barnraising::Broker::Server->new( $db, $accept_socket );
      STDOUT->printflush( " do handle_offer...\n" );
      $server->handle_offer();

    } otherwise {
      STDOUT->printflush( shift->stacktrace(), "\n" );
    } finally {
        $accept_socket->close();
    };
    exit 0;
  }

}




__END__

=head1 NAME

broker.pl

=head1 SYNOPSIS

broker.pl [options]

 Options:
   --broker-port N      listen on port N
   --reset              reset the MyDNS database and exits
   --create-zone Z      create the DNS zone Z and exits
   --mysql-connect H:P  connect to MySQL server on host H, port P
   --mysql-username U   use U for MySQL username
   --mysql-password P   use P for MySQL password
   --mydns-pid P        cause MyDNS to dump its cache when changes are made
   --help               print this help message and exit

=head1 OPTIONS

=over 8

=item B<--broker-port> I<N>

Listens for and accepts connections to port I<N>.  Defaults to B<777>.

=item B<--reset>

Completely purges the database used by MyDNS and recreates it from
scratch, and then exits immediately.  Can be combined with
B<--create-zone>.

=item B<--create-zone> I<ZONE>

Creates the DNS zone named I<ZONE> (for example:
B<imposter.lcs.mit.edu.>) and exits immediately.  Can be specified
multiple times to create multiple zones.  Can be combined with
B<--reset>.

=item B<--mysql-connect> I<HOST:PORT>

Directs the broker to connect to the MySQL database on the host
I<HOST> listening on port I<PORT>.  I<PORT> may be omitted.  Defaults
to B<localhost>.

=item B<--mysql-username> I<USER>

Directs the broker to use I<USER> as its MySQL username.  Defaults to
B<mydns>.

=item B<--mysql-password> I<PASS>

Directs the broker to use I<PASS> as its MySQL password.  Defaults to
B<mydns>.

=item B<--mydns-pid> I<PID>

If specified and nonzero, B<broker.pl> will send a SIGHUP to the
specified process ID every time the database changes.  If the process
is B<mydns>, this will cause it to dump its cache and reload (lazily)
from the up-to-date contents of the database.  Specifying this option
will result in B<mydns> always serving the most-up-to-date data, but
may decrease performance significantly under heavy load.

=item B<--help>

Prints a brief help message and exits.

=back

=head1 DESCRIPTION

B<broker.pl> serves requests to join Imposter proxy pools, and
maintains the database served by MyDNS.

=cut

