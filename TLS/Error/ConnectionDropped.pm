#
# TLS::Error::ConnectionDropped
#


package TLS::Error::ConnectionDropped;
use base qw( Error::Simple );

sub new {
  shift->SUPER::new( "connection dropped", @_ );
}




1;
