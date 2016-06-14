#
# TLS::Record
#
# This class represents a raw record on the wire.  It encapsulates the
# message type, protocol version, and payload fields, and provides
# encoding and decoding methods.
#


package TLS::Record;


use TLS::Error::ShortPacket;
use TLS::Alert;
use TLS::Handshake;

use Error;




sub new {
  my ($class, $content_type, $version_major, $version_minor,
      $payload, $mac_authenticator) = @_;
  # Construct a new object.
  bless {
	 CONTENT_TYPE      => $content_type,
	 VERSION_MAJOR     => $version_major,
	 VERSION_MINOR     => $version_minor,
	 ENCRYPTED_PAYLOAD => undef,
	 PAYLOAD           => $payload,
	 MAC_AUTHENTICATOR => $mac_authenticator,
	} => $class;
}


sub decode {
  my ($class, $packet, $cipher, $mac) = @_;

  my $header = substr($packet, 0, 5, "");
  length($header) >= 5
    or throw TLS::Error::ShortPacket "short TLS header: expected 5 bytes, got " . length($header) . " bytes";
  my ($content_type, $version_major, $version_minor, $length)
    = unpack "CCCn", $header;

  # Only SSLv3 and TLS are supported by this method.
  $version_major == 3 && $version_minor <= 1
    or throw Error::Simple "unsupported TLS version $version_major.$version_minor record received";

  # Extract payload from packet.
  length($packet) >= $length
    or throw TLS::Error::ShortPacket "short TLS packet: expected " . $length . " bytes, got " . length($packet) . " bytes";
  my $encrypted_payload = substr($packet, 0, $length, "");

  my ($payload, $mac_authenticator);
  if (defined $cipher) {
    # Decrypt payload.
    $payload = $cipher->decrypt( $encrypted_payload );

    # Strip off any MAC present, without checking its validity.
    $mac_authenticator = substr( $payload, -$mac->size, $mac->size, "" );
  } else {
    # Message is opaque ciphertext.
    $payload = $mac_authenticator = undef;
  }

  # Construct a new object.
  my $self = bless {
		    CONTENT_TYPE      => $content_type,
		    VERSION_MAJOR     => $version_major,
		    VERSION_MINOR     => $version_minor,
		    ENCRYPTED_PAYLOAD => $encrypted_payload,
		    PAYLOAD           => $payload,
		    MAC_AUTHENTICATOR => $mac_authenticator,
		   } => $class;

  return ($self, $packet);
}

sub content_type      { shift->{CONTENT_TYPE} }
sub version_major     { shift->{VERSION_MAJOR} }
sub version_minor     { shift->{VERSION_MINOR} }
sub encrypted_payload { shift->{ENCRYPTED_PAYLOAD} }
sub payload           { shift->{PAYLOAD} }
sub mac_authenticator { shift->{MAC_AUTHENTICATOR} }

sub is_change_cipher_spec { shift->content_type == 20 }
sub is_alert              { shift->content_type == 21 }
sub is_handshake          { shift->content_type == 22 }
sub is_application_data   { shift->content_type == 23 }

sub content_type_name {
  my ($self) = @_;
  if    ( $self->is_change_cipher_spec ) { return "change_cipher_spec"; }
  elsif ( $self->is_alert              ) { return "alert"; }
  elsif ( $self->is_handshake          ) { return "handshake"; }
  elsif ( $self->is_application_data   ) { return "application_data"; }
  else { throw Error::Simple "invalid TLS content type"; }
}


sub encode {
  my ($self, $cipher) = @_;
  my $encrypted_payload = $self->encrypted_payload;
  if ( !defined( $encrypted_payload ) ) {
    defined $cipher or throw Error::Simple "uh-oh, no cipher for encoding?  this should never happen.";
    my $plaintext = $self->payload . $self->mac_authenticator;
    $encrypted_payload = $cipher->encrypt( $plaintext );
  }
  my $header = pack( "CCCn",
		     $self->content_type,
		     $self->version_major, $self->version_minor,
		     length( $encrypted_payload ) );
  return $header . $encrypted_payload;
}


sub to_string {
  my ($self) = @_;

  my $text = sprintf("%i.%i %s ", $self->version_major,
		     $self->version_minor, $self->content_type_name );

  my $payload = $self->payload;
  if (defined $payload) {

    if ( $self->is_alert ) {
      $text .= TLS::Alert->decode( $payload )->to_string();
    } elsif ( $self->is_handshake ) {
      my @handshakes = TLS::Handshake->decode_all( $payload );
      $text .= join "\n  ", map { $_->to_string() } @handshakes;
    } elsif ( $self->is_change_cipher_spec ) {
      $text .= unpack("H*", $payload);
    } elsif ( $self->is_application_data ) {
      if ($payload =~ /[^\t\n\r\x20-\x7E]/) {
	$text .= "hex: " . unpack("H*", $payload);
      } else {
	$text .= "text: $payload";
      }
    }

  } else {

    $text .= "<encrypted payload>";

  }

  return $text;
}






1;
