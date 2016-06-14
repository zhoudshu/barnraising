#
# TLS::Cipher
#
# This class represents an abstract symmetric-key cipher.  The
# by_name() static method returns a factory (currently simply a
# package name), whose new() method is passed a key and an initial IV
# and returns a cipher context object.  The encrypt and decrypt
# methods perform the respective operations on the supplied buffer.
# Note that a cipher context corresponds to a stream of TLS record
# payloads, and these two operations update the current IV.
# Therefore, non-continguous record payloads MAY NOT be
# encrypted/decrypted by a single context without also processing the
# intervening payloads, and encryption and decryption MUST NOT be
# mixed in a single cipher context.  The result of any encryption or
# decryption which does not follow these rules is undefined.
#
# Subpackages:
#  TLS::Cipher::NULL
#    A null cipher, which passes input to output unchanged.  Does not
#    provide any confidentiality or any other security.
#

use strict;


package TLS::Cipher;

use Error;


sub by_name ($$) {
  my ($class, $name) = @_;
  my $classname = { qw[
		       NULL          TLS::Cipher::NULL
		       RC4_128       TLS::Cipher::RC4
		       DES_EDE3_CBC  TLS::Cipher::DES_EDE3_CBC_Inline_C
		      ] }->{$name};
  defined $classname or throw Error::Simple "no such cipher $classname";

  # Load the package if it is not yet loaded.  (We test for the
  # existence of the "new" method, since that is a required method for
  # this interface.)
  {
    no strict "refs";
    if ( ! exists( ${"${classname}::"}{"new"} ) ) {
      eval "use $classname";
      die $@ if $@;
    }
  }

  return $classname;
}

sub new ($$$) {
  my ($class, $key, $iv) = @_;
  throw Error::Simple "abstract method";
}
sub encrypt ($$) {
  my ($self, $buffer) = @_;
  throw Error::Simple "abstract method";
}
sub decrypt ($$) {
  my ($self, $buffer) = @_;
  throw Error::Simple "abstract method";
}


# Padding and unpadding functions compatible with SSL3.0/TLS1.0.  Note
# that these are only really necessary for block ciphers.
sub pad {
  my ( $class, $data, $blocksize ) = @_;
  my $padding_length = $blocksize - ( length( $data ) % $blocksize ) - 1;
  return $data . ( pack( "C", $padding_length ) x ( $padding_length + 1 ) );
}
sub unpad {
  my ( $class, $data ) = @_;
  return "" if $data eq "";
  my $padding_length = unpack( "C", substr( $data, -1 ) );
  return substr( $data, 0, length( $data ) - $padding_length - 1 );
}







package TLS::Cipher::NULL;
use base qw( TLS::Cipher );

sub new ($$$) {
  my ($class, $key, $iv) = @_;
  bless {} => $class;
}
sub encrypt ($$) {
  my ($self, $buffer) = @_;
  return $buffer;
}
sub decrypt ($$) {
  my ($self, $buffer) = @_;
  return $buffer;
}




1;
