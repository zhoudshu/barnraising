#
# TLS::SSLv2Record
#
# This class represents a raw SSLv2 record on the wire.  Since SSLv2
# records have less structure than TLS records, this simply
# encapsulates the header and the payload.
#


package TLS::SSLv2Record;

use TLS::Error::ShortPacket;


use Error;




sub new {
  my ($class) = @_;
  throw Error::Simple "internal error: TLS::SSLv2Record->new not implemented";
}


sub decode {
  my ($class, $packet, $cipher, $mac) = @_;

  length( $packet ) >= 1
    or throw TLS::Error::ShortPacket "short SSLv2 header: no bytes";

  my $first_byte = unpack( "C", $packet );
  my ($header_length, $length, $padding_length, $is_escape);
  $header_length = ($first_byte & 0x80) == 0 ? 3 : 2;

  my $header = substr( $packet, 0, $header_length, "" );
  length( $header ) == $header_length
    or throw TLS::Error::ShortPacket "short SSLv2 header: expected $header_length bytes, got " . length( $header ) . " bytes";

  if ($header_length == 3) {
    my ($b0, $b1, $b2) = unpack( "CCC", $header );
    $length = (($b0 & 0x3F) << 8) | $b1;
    $is_escape = ($b0 & 0x40) != 0;
    $padding_length = $b2;
  } else {
    my ($b0, $b1) = unpack( "CC", $header );
    $length = (($b0 & 0x7F) << 8) | $b1;
    $is_escape = 0;
    $padding_length = 0;
  }


  # Extract payload from packet.
  my $total_length = $length + $padding_length;
  length( $packet ) >= $total_length
    or throw TLS::Error::ShortPacket "short SSLv2 packet: expected $total_length bytes, got " . length( $packet ) . " bytes";
  my $encrypted_payload = substr($packet, 0, $total_length, "");

  my ($payload, $mac_authenticator);
  if (defined $cipher) {
    # Decrypt payload.
    # XXX CTL TLS style padding removal is WRONG here!
    $payload = $cipher->decrypt( $encrypted_payload );

    # Strip off any MAC present, without checking its validity.
    # In SSLv2, the MAC authenticator precedes the payload.
    $mac_authenticator = substr( $payload, 0, $mac->size, "" );
  } else {
    # Message is opaque ciphertext.
    $payload = $mac_authenticator = undef;
  }

  # Construct a new object.
  my $self = bless {
		    HEADER_LENGTH     => $header_length,
		    LENGTH            => $length,
		    IS_ESCAPE         => $is_escape,
		    PADDING_LENGTH    => $padding_length,
		    ENCRYPTED_PAYLOAD => $encrypted_payload,
		    PAYLOAD           => $payload,
		    MAC_AUTHENTICATOR => $mac_authenticator,
		   } => $class;

  return ($self, $packet);
}

sub header_length     ($) { shift->{HEADER_LENGTH} }
sub length            ($) { shift->{LENGTH} }
sub encrypted_payload ($) { shift->{ENCRYPTED_PAYLOAD} }
sub payload           ($) { shift->{PAYLOAD} }
sub mac_authenticator ($) { shift->{MAC_AUTHENTICATOR} }



sub encode {
  my ($self, $cipher) = @_;
  my $encrypted_payload = $self->encrypted_payload;
  if ( !defined( $encrypted_payload ) ) {
    throw Error::Simple "internal error: I don't support consing up SSLv2 records, sorry";

    # XXX CTL THIS DOES NOT WORK, FIX IT LATER.  Or maybe never.
    defined $cipher or throw Error::Simple "uh-oh, no cipher for encoding?  this should never happen.";
    my $plaintext = $self->mac_authenticator . $self->payload;
    $encrypted_payload = $cipher->encrypt( $plaintext );
  }

  my $header;
  if ($self->header_length == 3) {
    $header = pack( "CCC",
		    ($self->is_escape ? 0x40 : 0)
		    | (($self->length >> 8) & 0x3F),
		    ($self->length & 0xFF),
		    ($self->padding_length & 0xFF) );
  } else {
    $header = pack( "CC",
		    0x80 | (($self->length >> 8) & 0x7F),
		    ($self->length & 0xFF) );
  }
  return $header . $encrypted_payload;
}


sub to_string {
  my ($self) = @_;

  my $text = "2.0 " . unpack( "H*", $self->payload );

  return $text;
}


sub is_change_cipher_spec ($) { 0 }
sub is_alert              ($) { 0 }
sub is_handshake          ($) { 0 }
sub is_application_data   ($) { 0 }








1;
