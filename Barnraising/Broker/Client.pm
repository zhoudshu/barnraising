#
# Barnraising::Broker::Client
#

use strict;


package Barnraising::Broker::Client;


use Barnraising::Broker::Message;

use IO::Socket;
use Error qw( :try );



sub new ($$) {
  my ($class, $resource) = @_;
  STDOUT->print( "#PeerAddr: " . $resource->broker_host . "\n" );
  STDOUT->print( "#PeerPort: " . $resource->broker_port . "\n" );

  my $socket = IO::Socket->new(
			       Domain   => AF_INET,
			       Type     => SOCK_STREAM,
			       Proto    => "tcp",
			       PeerAddr => $resource->broker_host,
			       PeerPort => $resource->broker_port,
			      )
    or throw Error::Simple "IO::Socket->new (connect): $@ ($!)";

  my $self = bless {
		    SOCKET   => $socket,
		    RESOURCE => $resource,
		    LOG      => \*STDOUT, # XXX or \*STDERR
		   } => $class;

  try {

    $self->hello();

  } otherwise {
    $self->close();
    shift->throw();
  };

  return $self;
}

sub socket   ($) { shift->{SOCKET} }
sub resource ($) { shift->{RESOURCE} }
sub log      ($) { shift->{LOG} }


sub close ($) {
  my ($self) = @_;
  $self->socket->shutdown( 2 );
}



sub hello {
  my ($self) = @_;

  Barnraising::Broker::Message::Hello
      -> new( Role => "Minion" )
	-> write( $self->log )
	  -> write( $self->socket );

  Barnraising::Broker::Message::Hello
    -> read( $self->socket )
      -> write( $self->log )
	-> get( Role         => \my $other_role,
		Capabilities => \my @other_capabilities );
  # XXX check contents of server hello
}

sub offer ($%) {
  my ($self, %attr) = @_;

  my $services = $attr{Services};

  Barnraising::Broker::Message::Offer
      -> new( Resource => $self->resource->uri,
	      Services => [map { $_->tag } @$services] )
	-> write( $self->log )
	  -> write( $self->socket );

  my @daemons = ();

 ACCEPT: while (1) {
    my $service;
    try {
      Barnraising::Broker::Message::Accept
	  -> read( $self->socket )
	    -> write( $self->log )
	      -> get( Service => \my $service_tag );
      ($service) = grep { $_->tag eq $service_tag } @$services;
      defined( $service )
	or throw Error::Simple "service $service_tag not offered";
    } catch Mimic::Error::EOF with {
      # Ignore warning about exiting subroutine via "last".
      $SIG{__WARN__} = sub {};
      last ACCEPT;
    };

    my ($daemon) = $service->negotiate( Resource => $self->resource,
					Client   => $self );
    push @daemons, $daemon;
  }

  STDOUT->print( "#daemons: " . scalar(@daemons) . "\n" );

  return @daemons;
}





1;
