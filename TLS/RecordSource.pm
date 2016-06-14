#
# TLS::RecordSource
#
# This class represents a source of TLS::Record objects, which are
# decoded from the byte stream passed to its constructor.
#


package TLS::RecordSource;

use TLS::Cipher;
use TLS::MAC;

use Error qw(:try);


sub new ($$) {
  my ($class, %attrs) = @_;
  my $handle = $attrs{"Handle"};
  my $buffer = $attrs{"Buffer"};
  bless {
	 HANDLE  => $handle,
	 BUFFER  => defined( $buffer ) ? $buffer : "",
	 RECORD_COUNT => 0,
	 CIPHER  => TLS::Cipher::NULL->new(),
	 MAC     => TLS::MAC::NULL,
	} => $class;
}

sub handle  ($) { shift->{HANDLE} }
sub cipher  ($) { shift->{CIPHER} }
sub mac     ($) { shift->{MAC} }


sub set_cipher {
  my ($self, $new_cipher) = @_;
  $self->{CIPHER} = $new_cipher;
  return $self;
}

sub set_mac {
  my ($self, $new_mac) = @_;
  $self->{MAC} = $new_mac;
  return $self;
}


sub get ($) {
  my ($self) = @_;
  my $buffer = $self->{BUFFER};
  my $record = undef;
  do {
    try {

      ($record, $buffer) = $self->decode( $buffer );

    } catch TLS::Error::ShortPacket with {

      defined $self->handle or throw TLS::Error::ConnectionDropped;

      # XXX CTL disable this debugging trace message.
      if (0 && $buffer ne "") {
	STDERR->print( " Buffer: ", unpack("H*",$buffer), "\n" );
	STDERR->print( shift->stacktrace );
	STDERR->print( "No complete record available, reading from socket.\n");
      }

      defined $self->handle->sysread( my $read_buffer, 1<<15 )
	or throw Error::Simple "read: $!";
      $buffer .= $read_buffer;

      $read_buffer ne "" or throw TLS::Error::ConnectionDropped;

    };
  } while !defined( $record );

  $self->{BUFFER} = $buffer;

  return $record;
}


# This is part of the interface presented to subclasses, which can
# override this method to provide a different decoder.  This method
# should return a two-element list: an instance of TLS::Record (or a
# subclass), and the "rest" of the buffer.  It should throw
# TLS::Error::ShortPacket if there is not enough data in the buffer to
# decode a record.
sub decode_tls ($$) {
  my ($self, $buffer) = @_;
  return TLS::Record->decode( $buffer, $self->cipher, $self->mac );
}

sub decode_sslv2 ($$) {
  my ($self, $buffer) = @_;
  return TLS::SSLv2Record->decode( $buffer, $self->cipher, $self->mac );
}

sub decode ($$) {
  my ($self, $buffer) = @_;
  my ($record, $rest);

  if ($self->{RECORD_COUNT} == 0) {

    # First record --- try to figure out whether it's SSLv2, SSLv3, or
    # TLS from the buffer.  Rescorla (in "SSL & TLS") recommends that
    # the first incoming byte be tested for equality with 0x16, which
    # is the SSLv3/TLS "Handshake" content-type; if it is any other
    # value, it must be SSLv2.  An SSLv2 client will never send 0x16
    # as the first byte because that would correspond to a very long
    # (> 5 KB) SSLv2 ClientHello.
    my $first_byte = unpack( "C", $buffer );
    if (!defined( $first_byte ) || ($first_byte & 0x7F) >= 0x16) {
      ($record, $rest) = $self->decode_tls( $buffer );
    } else {
      ($record, $rest) = $self->decode_sslv2( $buffer );
    }

  } else {

    # Expect all subsequent records to be SSLv3/TLS --- we don't support SSLv2.
    ($record, $rest) = $self->decode_tls( $buffer );

  }

  $self->{RECORD_COUNT}++;

  return ($record, $rest);
}




1;
