#
# TLS::Cipher::CBC
#
# An abstract base class for block ciphers used in CBC mode with
# SSL's custom padding mode.
#

use strict;


package TLS::Cipher::CBC;
use base qw( TLS::Cipher );

use Crypt::CBC;


sub new ($$$$) {
  my ($class, $block_cipher, $key, $iv) = @_;
  my $crypt = Crypt::CBC->new( {
				cipher => $block_cipher,
				key    => $key,
				iv     => $iv,
				regenerate_key => 0,
				prepend_iv     => 0,
				padding => sub {
				  my ($data, $blocksize, $direction) = @_;
				  $direction =~ /^d/
				    ? $class->unpad( $data )
				    : $class->  pad( $data, $blocksize );
				}
			       } );
  bless {
	 BLOCKSIZE => $block_cipher->blocksize,
	 CRYPT     => $crypt,
	} => $class;
}

sub encrypt ($$) {
  my ($self, $plaintext) = @_;
  my $ciphertext = $self->{CRYPT}->encrypt( $plaintext );
  my $new_iv = substr( $ciphertext, -$self->{BLOCKSIZE} );
  local($SIG{__WARN__}) = sub{}; # Get rid of annoying "don't reset IV" warning
  $self->{CRYPT}->set_initialization_vector( $new_iv );
  return $ciphertext;
}

sub decrypt ($$) {
  my ($self, $ciphertext) = @_;
  my $plaintext = $self->{CRYPT}->decrypt( $ciphertext );
  my $new_iv = substr( $ciphertext, -$self->{BLOCKSIZE} );
  local($SIG{__WARN__}) = sub{}; # Get rid of annoying "don't reset IV" warning
  $self->{CRYPT}->set_initialization_vector( $new_iv );
  return $plaintext;
}





1;
