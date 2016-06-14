#
# Barnraising::ImpTLS::RecordSource
#
# This class, similar to TLS::RecordSource, represents a source of
# Barnraising::ImpTLS::Record objects, which are decoded from the byte stream
# passed to its constructor.
#


package Barnraising::ImpTLS::RecordSource;
use base qw( TLS::RecordSource );

use Barnraising::ImpTLS::Record;
use Barnraising::ImpTLS::SSLv2Record;
use TLS::Cipher;
use TLS::MAC;


sub decode_tls ($$) {
  my ($self, $buffer) = @_;
  Barnraising::ImpTLS::Record->decode( $buffer, $self->cipher, $self->mac );
}

sub decode_sslv2 ($$) {
  my ($self, $buffer) = @_;
  Barnraising::ImpTLS::SSLv2Record->decode( $buffer, $self->cipher, $self->mac );
}


1;
