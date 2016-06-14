#
# TLS::MAC
#
# This class represents a Message Authentication Code.
# Subpackages:
#  TLS::MAC::NULL          No MAC (i.e., no integrity protection)
#  TLS::MAC::HMAC          An abstract base for HMACs (RFC 2104)
#  TLS::MAC::HMAC::SHA1    HMAC-SHA1
#


package TLS::MAC;

use Error;

sub by_name {
  my ($class, $name) = @_;
  my $classname = {
		   NULL => TLS::MAC::NULL,
		   MD5  => TLS::MAC::HMAC::MD5,
		   SHA1 => TLS::MAC::HMAC::SHA1,
		  }->{$name};
  defined $classname or throw Error::Simple "no such MAC $name";
  return $classname;
}



sub size { throw Error::Simple "abstract method"; }




package TLS::MAC::NULL;
use base qw( TLS::MAC );

sub size { 0 }



package TLS::MAC::HMAC;
use base qw( TLS::MAC );



package TLS::MAC::HMAC::MD5;
use base qw( TLS::MAC::HMAC );

sub size { 16 }




package TLS::MAC::HMAC::SHA1;
use base qw( TLS::MAC::HMAC );

sub size { 20 }





1;
