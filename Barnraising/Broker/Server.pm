#
# Barnraising::Broker::Server
#

use strict;


package Barnraising::Broker::Server;

use Barnraising::Resource;
use Barnraising::Broker::Message;
use Barnraising::Broker::Database;
use MyDNS::Database;
use MyDNS::Zone;

use Error qw( :try );



sub new ($$$) {
  my ($class, $db, $socket) = @_;

  my $self = bless {
		    DB     => $db,
		    SOCKET => $socket,
		    LOG    => \*STDOUT, # XXX or \*STDERR
		   } => $class;
  $self->hello();
  return $self;
}

sub db     ($) { shift->{DB} }
sub socket ($) { shift->{SOCKET} }
sub log    ($) { shift->{LOG} }

sub hello ($) {
  my ($self) = @_;

  Barnraising::Broker::Message::Hello
      -> new( Role => "Broker" )
	-> write( $self->log )
	  -> write( $self->socket );

  Barnraising::Broker::Message::Hello
      -> read( $self->socket )
	-> write( $self->log )
	  -> get( Role         => \my $other_role,
		  Capabilities => \my @other_capabilites );
  # XXX should look at Role and Capabilities parameters here.
}


sub handle_offer ($) {
  my ($self) = @_;

  Barnraising::Broker::Message::Offer
      -> read( $self->socket )
	-> write( $self->log )
	  -> get( Resource => \my $resource_uri,
		  Services => \my @service_tags );

  my $minion_address = $self->socket->peerhost || "127.0.0.1";
  STDOUT->print( "Remote address: $minion_address Resource $resource_uri @service_tags \n" );

#  my $resource = $self->db->lookup_resource( $resource_uri );
  my $resource = Barnraising::Resource->new( $resource_uri );
  my @services = map {
    try { Barnraising::Service->from_tag( $_ ) } otherwise { () };
  } @service_tags;
  $resource->handle_offer( Server        => $self,
			   MinionAddress => $minion_address,
			   Services      => \@services );
}


sub accept_service ($%) {
  my ($self, %attr) = @_;

  my $service = $attr{Service};

  Barnraising::Broker::Message::Accept
      -> new( Service => $service->tag )
	-> write( $self->log )
	  -> write( $self->socket );

  $service->accept( Server        => $self,
		    Resource      => $attr{Resource},
		    MinionAddress => $attr{MinionAddress} );
}





1;
