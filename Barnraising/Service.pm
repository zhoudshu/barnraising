#
# Barnraising::Service
#

use strict;


package Barnraising::Service;

use Error;


sub from_tag ($$) {
  my ($class, $tag) = @_;
  my @classes = qw( Barnraising::Service::ImpTLS
                    Barnraising::Service::Cache );
  for my $c (@classes) {
    if ($c->tag eq $tag) {
      return $c;
    }
  }
  throw Error::Simple "no known service matching $tag";
}





package Barnraising::Service::ImpTLS;
use base qw( Barnraising::Service );



sub tag ($) { "ImpTLS" }

sub negotiate ($%) {
  my ($class, %attr) = @_;
  my ($client, $resource) = ( $attr{Client}, $attr{Resource} );

  Barnraising::Service::ImpTLS::Accept
      -> read( $client->socket )
	-> write( *STDOUT )
	  -> get( "Listen-Ports" => \my @listen_ports,
		  "Primary"      => \my $primary,
		  "Expander"     => \my $expander );

  my $daemon = Barnraising::Service::ImpTLS::Daemon
    -> new( Listen_Ports => \@listen_ports,
	    Primary      => $primary,
	    Expander     => $expander );

  Barnraising::Service::ImpTLS::Ready
      -> new( "Listen-Port" => $daemon->listen_port,
	      "Expires"     => $daemon->expires )
	-> write( *STDOUT )
	  -> write( $client->socket );

  Barnraising::Service::ImpTLS::Confirmed
      -> read( $client->socket )
	-> write( *STDOUT )
	  -> get( Names => \my @names );

  return $daemon;
}

sub accept ($%) {
  my ($class, %attr) = @_;
  my ($server, $resource) = ( $attr{Server}, $attr{Resource} );

  Barnraising::Service::ImpTLS::Accept
      -> new( "Listen-Ports" => ["443", "4433", "*"],
	      "Primary"      => $resource->imptls_primary,
	      "Expander"     => $resource->expander_primary )
	-> write( *STDOUT )
	  -> write( $server->socket );

  Barnraising::Service::ImpTLS::Ready
      -> read( $server->socket )
	-> write( *STDOUT )
	  -> get( "Listen-Port" => \my $listen_port,
		  "Expires"     => \my $expires );

  my $hostname = $class->create_dns_records( $server->db->mydns,
					     $resource,
					     $attr{MinionAddress} );

  Barnraising::Service::ImpTLS::Confirmed
      -> new( Names => [ $hostname ] )
	-> write( *STDOUT )
	  -> write( $server->socket );
}

sub create_dns_records {
  my ($self, $mydns_db, $resource, $ip_address) = @_;

  my $zone = $mydns_db->lookup_zone( $resource->domain );

  my $hostname = "www";
  $zone->create_rr( "A", $hostname, $ip_address );

  return $hostname;
}



package Barnraising::Service::ImpTLS::Accept;
use base qw( Mimic::Message::Simple );

sub tag { "Barnraising/Broker/1.0/ImpTLS/Accept" }
sub required_params { qw( Listen-Ports Primary Expander ) }
sub optional_params { () }

package Barnraising::Service::ImpTLS::Ready;
use base qw( Mimic::Message::Simple );

sub tag { "Barnraising/Broker/1.0/ImpTLS/Ready" }
sub required_params { qw( Listen-Port Expires ) }
sub optional_params { () }

package Barnraising::Service::ImpTLS::Confirmed;
use base qw( Mimic::Message::Simple );

sub tag { "Barnraising/Broker/1.0/ImpTLS/Confirmed" }
sub required_params { qw( ) }
sub optional_params { qw( Names ) }



package Barnraising::Service::ImpTLS::Daemon;

use Barnraising::ImpTLS::TLSRecordSource;
use TLS::RecordSink;
use TLS::Error::ConnectionDropped;

use IO::Socket;
use POSIX;
use Error qw( :try );

sub new ($%) {
  my ($class, %attr) = @_;
  my $listen_ports = $attr{Listen_Ports};
  my $primary      = $attr{Primary};
  my $expander     = $attr{Expander};

  # Create a socket listening on an SSL proxy incoming port.
  # XXX should check which ports are permitted based on resource,
  # e.g. filter through $resource->permitted_ports( @$listen_ports )
  my $listen_socket = $class->open_listen_socket( @$listen_ports );
  my $listen_port = $listen_socket->sockport();

  # Create a subprocess to handle forwarding incoming connections.
  my $kid_pid = $class->spawn_forwarding_daemon( $listen_socket,
						 $primary,
						 $expander );

  # In the parent process, close the listening socket.
  $listen_socket->close();

  bless {
	 LISTEN_PORT   => $listen_port,
	 PRIMARY       => $primary,
	 KID_PID       => $kid_pid,
	} => $class;
}

sub listen_port   ($) { shift->{LISTEN_PORT} }
sub primary       ($) { shift->{PRIMARY} }
sub kid_pid       ($) { shift->{KID_PID} }

sub expires ($) { time() + 24*60*60 }

sub wait ($) {
  my ($self) = @_;
  my $kid_pid = $self->kid_pid;
  STDOUT->print( "Forwarding daemon spawned, pid $kid_pid.\n" );
  waitpid $kid_pid, 0;
}

sub open_listen_socket ($@) {
  my ($class, @ports) = @_;
  for my $port (@ports) {
    #
    # At one point I needed to set the listen queue to 100 as a kludgey
    # workaround to some performance problem.  I can't remember what it
    # was now, so I've changed it back.  2003-07-15 CTL
    #
    my $socket = IO::Socket->new( Domain => AF_INET,
				  Type   => SOCK_STREAM,
				  Proto  => "tcp",
				  Listen => 5,
				  LocalPort => $port eq "*" ? undef : $port );
    if ($socket) { return $socket; }
  }
  throw Error::Simple "could not bind to any of the ports (@ports), last error: $@ ($!)";
}

sub spawn_forwarding_daemon ($$$$) {
  my ($class, $listen_socket, $primary, $expander) = @_;

  defined( my $kid = fork() ) or throw Error::Simple "fork: $!";
  # In the parent process, return and complete the broker negotiation.
  return $kid if $kid;


  # Turn off the child reaper: we want to reap children manually.  We use
  # this to limit the number of child processes.
  local( $SIG{CHLD} ) = "DEFAULT";
  my $forwarding_process_limit = 50;


  # In the child process, go into the main accept-fork-handle loop.
  STDOUT->print( "Entering ImpTLS accept loop, forwarding to $primary expander $expander ...\n" );
  while (1) {

    if ( --$forwarding_process_limit < 0 ) {
      # Wait for a child to die before starting a new one.
      CORE::wait();
      $forwarding_process_limit++;
    }

    my $accept_socket = $listen_socket->accept();
    if ( !defined( $accept_socket ) ) {
      # ECONNABORTED should result in retry.
      STDOUT->print("warn: accept: $!\n"), redo if $! == POSIX::ECONNABORTED;
      throw Error::Simple "IO::Socket->accept: $@ ($!)";
    }

    defined( my $kid = fork() ) or throw Error::Simple "fork: $!";
    if ( $kid ) {
      # In parent, close the socket to decrease refcount.
      $accept_socket->close();
    } else {
      # In child, handle forwarding the connection.

      # XXX horrible kludge!  Normally we would not continually retry
      # connecting until the end of time.  This should be removed
      # in production code; it should be replaced with some sort of
      # connection-pool mechanism which opens outgoing connections before
      # accepting incoming connections.
      my $connect_socket;
      until ( $connect_socket ) {
	use POSIX;
    warn("connect: to $primary");
	$connect_socket = IO::Socket->new( Domain   => AF_INET,
					   Type     => SOCK_STREAM,
					   Proto    => "tcp",
					   PeerAddr => $primary )
	  or ( $! == POSIX::ETIMEDOUT and warn("connect: timeout $!"), sleep(1) )
	    or ( $! == POSIX::ECONNREFUSED and warn("connect: connrefused $!"), sleep(1) )
	      or throw Error::Simple "IO::Socket->new (connect): $@ ($!)";
      }

      # Set large buffer sizes and keepalives.
      $accept_socket->sockopt( SO_RCVBUF, 0x11000 );
      $accept_socket->sockopt( SO_SNDBUF, 0x11000 );
      $accept_socket->sockopt( SO_KEEPALIVE, 1 );
      $connect_socket->sockopt( SO_RCVBUF, 0x11000 );
      $connect_socket->sockopt( SO_SNDBUF, 0x11000 );
      $connect_socket->sockopt( SO_KEEPALIVE, 1 );

      # Disable the Nagle algorithm on both sockets.
      $accept_socket
	->setsockopt( Socket::IPPROTO_TCP(), Socket::TCP_NODELAY(), 1 );
      $connect_socket
	->setsockopt( Socket::IPPROTO_TCP(), Socket::TCP_NODELAY(), 1 );

      # Forward records in both directions over the wire.
      $class->bidirectional_forward_tls( $accept_socket, $connect_socket,
					 $expander );

      exit 0;
    }

  }
}

sub bidirectional_forward_tls ($$$$) {
  my ($class, $accept_socket, $connect_socket, $expander) = @_;

  my  $accept_host =  $accept_socket->peerhost || "127.0.0.1";
  my $connect_host = $connect_socket->peerhost || "127.0.0.1";
  my $connect_port = $connect_socket->peerport;
  STDOUT->print( "Accepted connection from $accept_host, forwarding to $connect_host:$connect_port...\n" );

  defined( my $kid = fork() ) or throw Error::Simple "fork: $!";
  if ($kid) {
    try {
      $class->forward_tls_records( "S->C: ", $connect_socket, $accept_socket,
				   $expander );
    } finally {
      # Don't die without waiting for the kid to die.
      waitpid $kid, 0;
    };
  } else {
    $class->forward_tls_records( "C->S: ", $accept_socket, $connect_socket,
				 $expander );
  }
}


sub forward_tls_records ($$$$$) {
  my ($class, $direction_sigil, $read_socket, $write_socket, $expander) = @_;

  my $reader = Barnraising::ImpTLS::TLSRecordSource->new
    ( Handle => $read_socket, Expander => $expander );
  my $writer = TLS::RecordSink->new( Handle => $write_socket );

  try {
    while (1) {

      my $record = $reader->get();
      #STDOUT->printflush( $direction_sigil, $record->to_string, "\n" );
      STDOUT->printflush( $direction_sigil, "\n" );
      $writer->put( $record );

      if ( $record->is_new_cipher_event ) {
	# Imposter has received a new key for this stream.
	$writer->set_cipher( $record->cipher );
      }

    }
  } catch TLS::Error::ConnectionDropped with {
#    STDOUT->printflush( $direction_sigil, "connection dropped\n" );
  } catch Error::Simple with {
    STDERR->printflush( $direction_sigil, shift->stacktrace );
  } finally {
    $write_socket->shutdown( 1 );
  };
}













package Barnraising::Service::Cache;
use base qw( Barnraising::Service );

sub tag ($) { "Cache" }


sub negotiate ($%) {
  my ($class, %attr) = @_;
  my ($client, $resource) = ( $attr{Client}, $attr{Resource} );

  Barnraising::Service::Cache::Accept
      -> read( $client->socket )
	-> write( *STDOUT )
	  -> get( Primary => \my $primary );

  return Barnraising::Service::Cache::Daemon->new( Primary => $primary );
}

sub accept ($%) {
  my ($class, %attr) = @_;
  my ($server, $resource) = ( $attr{Server}, $attr{Resource} );

  Barnraising::Service::Cache::Accept
      -> new( Primary => $resource->expander_primary )
	-> write( *STDOUT )
	  -> write( $server->socket );
}



package Barnraising::Service::Cache::Accept;
use base qw( Mimic::Message::Simple );

sub tag { "Barnraising/Broker/1.0/Cache/Accept" }
sub required_params { qw( Primary ) }
sub optional_params { () }



package Barnraising::Service::Cache::Daemon;

sub new ($%) {
  my ($class, %attr) = @_;
  my $primary = Barnraising::Expander::Remote->new( $attr{Primary} );
  my $cache = Barnraising::Expander::Cache->new( $primary );

  bless {
	 CACHE => $cache,
	} => $class;
}

sub cache ($) { shift->{CACHE} }

sub wait ($) {
  my ($self) = @_;
  # Do nothing; this daemon has no need to block.
}





1;
