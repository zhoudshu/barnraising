#
# TLS::RecordSink
#
# This class can accept TLS::Record objects, which it encodes and sends
# out on the byte stream passed to its constructor.
#


package TLS::RecordSink;

use TLS::Cipher;

use Error;


sub new {
  my ($class, %attr) = @_;
  my $handle = $attr{"Handle"};
  bless {
	 HANDLE => $handle,
	 CIPHER => TLS::Cipher::NULL->new(),
	} => $class;
}

sub handle { shift->{HANDLE} }
sub cipher { shift->{CIPHER} }


sub set_cipher {
  my ($self, $new_cipher) = @_;
  $self->{CIPHER} = $new_cipher;
  return $self;
}


sub put {
  my ($self, $record) = @_;

  my $encoded_record = $record->encode( $self->cipher );

  if ($record->is_change_cipher_spec) { $self->{CIPHER} = undef; }

  my $sent_length = $self->handle->syswrite( $encoded_record );
  defined( $sent_length )
    or throw Error::Simple "syswrite TLS record error: $!";
  $sent_length == length( $encoded_record )
    or throw Error::Simple "short send (sent $sent_length, expected "
      . length( $encoded_record ) . "): $!";

  return $self;
}




1;
