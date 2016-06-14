#
# TLS::Cipher::RC4
#


package TLS::Cipher::RC4;
use base qw( TLS::Cipher );

use Crypt::RC4;


sub new ($$$) {
  my ($class, $key, $iv) = @_;
  my $rc4 = Crypt::RC4->new( $key );
  bless { RC4 => $rc4 } => $class;
}

sub rc4 ($) { shift->{RC4} }

sub encrypt ($$) {
  my ($self, $buffer) = @_;
  return $self->rc4->RC4( $buffer );
}
sub decrypt ($$) {
  my ($self, $buffer) = @_;
  return $self->rc4->RC4( $buffer );
}





1;
