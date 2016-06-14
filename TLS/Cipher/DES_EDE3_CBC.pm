#
# TLS::Cipher::DES_EDE3_CBC
#
# Triple-DES used in CBC mode.
#

use strict;


package TLS::Cipher::DES_EDE3_CBC;
use base qw( TLS::Cipher::CBC );

use Crypt::DES_EDE3;


sub new ($$$) {
  my ($class, $key, $iv) = @_;
  $class->SUPER::new( Crypt::DES_EDE3 => $key, $iv );
}




1;
