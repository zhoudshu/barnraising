#
# Barnraising::ImpTLS::Record
#


package Barnraising::ImpTLS::Record;
use base qw( TLS::Record );

use TLS::Error::ShortPacket;
use TLS::Cipher;
use TLS::MAC;




$CIPHER_NULL = TLS::Cipher::NULL->new();
$MAC_NULL = TLS::MAC::NULL;


sub decode ($$$$) {
  my ($class, $packet, $cipher, $mac) = @_;

  # Check content-type byte's high bit.
  if (ord($packet) & 0x80) {
    # Handle wrapped packets specially --- no encryption or mac!

    my ($self, $rest)
      = $class->SUPER::decode( $packet, $CIPHER_NULL, $MAC_NULL );

    my $wrapped_payload = $self->payload;
    length($wrapped_payload) >= 6
      or throw TLS::Error::ShortPacket "short Imposter wrapped packet";
    my ($encoding, $id, $mac) = unpack( "n n/a* n/a*", $wrapped_payload );

    $self->{PAYLOAD_ENCODING}  = $encoding;
    $self->{PAYLOAD_ID}        = $id;
    $self->{MAC_AUTHENTICATOR} = $mac;

    return ($self, $rest);

  } else {
    # Normal TLS packet or Imposter key_expose packet.
    return $class->SUPER::decode($packet, $cipher, $mac);
  }
}

sub payload_encoding ($) { shift->{PAYLOAD_ENCODING} }
sub payload_id       ($) { shift->{PAYLOAD_ID} }



sub is_imposter_wrapped ($) { shift->content_type & 0x80 }

sub is_key_expose       ($) { shift->content_type == 88 }

sub is_imposter_record ($) {
  my ($self) = @_;
  return $self->is_key_expose || $self->is_imposter_wrapped;
}

sub is_new_cipher_event ($) { 0 }


sub content_type_name ($) {
  my ($self) = @_;
  if    ( $self->is_key_expose       ) { return "key_expose"; }
  elsif ( $self->is_imposter_wrapped ) {
    return "wrapped(" . $self->content_type . ")";
  }
  else { return $self->SUPER::content_type_name(); }
}






1;
