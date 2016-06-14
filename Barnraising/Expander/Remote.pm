#
# Barnraising::Expander::Remote
#


package Barnraising::Expander::Remote;
# XXX formalize the interface
#use base qw( Barnraising::Expander );

use IO::Socket;


sub new ($$) {
  my ($class, $spec) = @_;
  print("Remote address $spec\n");
  bless {
      CACHE_DIR => "$ENV{HOME}/test/impcache",
      #CACHE_DIR => "/var/cache/imptls",
	 SPEC      => $spec,
	 SOCKET    => undef,
	} => $class;
}

sub cache_dir ($) { shift->{CACHE_DIR} }

# Connect to the server the first time we try to access the socket.
sub socket ($) {
  my ($self) = @_;
  $self->{SOCKET} ||= IO::Socket->new(
				      Domain   => AF_INET,
				      Type     => SOCK_STREAM,
				      Proto    => "tcp",
				      PeerAddr => $self->{SPEC},
				     )
    or throw Error::Simple "IO::Socket->new (connect): $@ ($!)";
  return $self->{SOCKET};
}


sub expand ($$$) {
  my ($self, $encoding, $id) = @_;
  print("Remote address get from server $encoding\n");
  if ($encoding == 1) {
    return $id;
  } elsif ($encoding == 2 || $encoding == 3) {
    return $self->get_from_server( $encoding, $id );
  }
}


sub get_from_server ($$$) {
  my ($self, $encoding, $id) = @_;

  Barnraising::Expander::Remote::Get
      -> new( Encoding => $encoding, ID => $id )
	-> write( $self->socket );

  Barnraising::Expander::Remote::Return
      -> read( $self->socket )
	-> get( Value => \my $data );

  return $data;
}




package Barnraising::Expander::Remote::Get;
use base qw( Mimic::Message::Simple );

sub tag { "Barnraising/Expander/1.0/Get" }
sub required_params { qw( Encoding ID ) }
sub optional_params { () }


package Barnraising::Expander::Remote::Return;
use base qw( Mimic::Message::Simple );

sub tag { "Barnraising/Expander/1.0/Return" }
sub required_params { qw( Value ) }
sub optional_params { () }




1;
