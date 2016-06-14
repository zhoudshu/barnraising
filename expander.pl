#! /usr/bin/perl -w
#
# barnraising - system for sharing bandwidth with overloaded Web servers
# barnraising-expander - server daemon for "publishing" payloads
#
# Copyright 2003 Christopher Lesniewski-Laas
# $Id: expander.pl,v 1.10 2003/07/15 19:40:49 ctl Exp $
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

use Getopt::Long;
use Pod::Usage;
use Error qw( :try );
$Error::Debug = $ENV{ERROR_DEBUG};

use IO::File;
use IO::Socket;
use IO::Handle;

use Barnraising::Expander::Remote;



# Process options.
my $opt_expander_port = 778;
my $opt_publish_dir = $ENV{IMP1_SHARED_DATA_DIRECTORY} || "/var/cache/imptls";
my $opt_help;
GetOptions(
	   "expander-port=i"  => \$opt_expander_port,
	   "publish-dir=s"    => \$opt_publish_dir,
	   "help|?"           => \$opt_help,
	  )
  or pod2usage(2);
$opt_help and pod2usage(1);



sub expand {
  my ($encoding, $id) = @_;
  my $hex = unpack( "H*", $id );
  my $filename = "$opt_publish_dir/$encoding.$hex";
  print("receive one block query $filename \n");
  my $f = IO::File->new( $filename, "r" )
    or throw Error::Simple "can't open cache file $filename for reading: $!";
  local ($/) = undef;
  return scalar <$f>;
}



# Set up a child reaper.
$SIG{CHLD} = sub { wait; };


# Create the listening socket.
my $listen_socket = IO::Socket->new( Domain => AF_INET,
				     Type   => SOCK_STREAM,
				     Proto  => "tcp",
				     Listen => 5,
				     LocalPort => $opt_expander_port )
  or throw Error::Simple "IO::Socket->new (listen): $@";

my $port = $listen_socket->sockport();
STDOUT->printflush( "Listening on $port...\n" );

# Main accept-fork-handle loop.
while (1) {

  my $accept_socket = $listen_socket->accept()
    or throw Error::Simple "IO::Socket->accept: $@ ($!)";

  defined( my $kid = fork() ) or throw Error::Simple "fork: $!";
  if ($kid) {
    # In parent, close the accepted socket to decrease refcount.
    $accept_socket->close();
  } else {
    # In child, handle the connection.
    try {

      while (1) {

	Barnraising::Expander::Remote::Get
	    -> read( $accept_socket )
	      -> get( Encoding => \my $encoding,
		      ID       => \my $id );

	$encoding =~ /^\d+$/
	  or throw Error::Simple "encoding should be an integer";

	my $data = &expand( $encoding, $id );

    STDOUT->printflush( "Expander get data from local content \n" );
	Barnraising::Expander::Remote::Return
	    -> new( Value => $data )
	      -> write( $accept_socket );

      }

    } otherwise {
      STDOUT->printflush( shift->stacktrace(), "\n" );
    } finally {
      $accept_socket->close();
    };

    ##zhoudshu added for ignoring exit and continue to accept request
    #exit 0;
  }

}




__END__

=head1 NAME

barnraising-expander

=head1 SYNOPSIS

barnraising-expander [options]

 Options:
   --expander-port N    listen on port N
   --publish-dir D      publish payloads in directory D
   --help               print this help message and exit

=head1 OPTIONS

=over 8

=item B<--expander-port> I<N>

Listens for and accepts connections to port I<N>.  Defaults to B<778>.

=back

=head1 DESCRIPTION


=cut

