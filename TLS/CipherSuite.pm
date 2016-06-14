#
# TLS::CipherSuite
#

use strict;


package TLS::CipherSuite;

use TLS::Cipher;
use TLS::MAC;


sub new {
  my ($class, $name, $auth, $key_ex, $cipher_name, $mac_name, $number) = @_;
  my $cipher = TLS::Cipher->by_name( $cipher_name );
  my $mac = TLS::MAC->by_name( $mac_name );
  bless {
	 NAME => $name,
	 AUTH => $auth,
	 KEY_EX => $key_ex,
	 CIPHER => $cipher,
	 MAC    => $mac,
	 NUMBER => hex( $number ),
	} => $class;
}

sub name           { shift->{NAME} }
sub authentication { shift->{AUTH} }
sub key_exchange   { shift->{KEY_EX} }
sub cipher         { shift->{CIPHER} }
sub mac            { shift->{MAC} }
sub number         { shift->{NUMBER} }

sub to_string { shift->name }






my @cipher_suites = map { TLS::CipherSuite->new( @$_ ) }
  [qw[    TLS_NULL_WITH_NULL_NULL        NULL NULL         NULL NULL 0x0000 ]],
  [qw[     TLS_RSA_WITH_NULL_MD5          RSA  RSA         NULL  MD5 0x0001 ]],
  [qw[     TLS_RSA_WITH_NULL_SHA          RSA  RSA         NULL SHA1 0x0002 ]],
  [qw[     TLS_RSA_WITH_RC4_128_MD5       RSA  RSA      RC4_128  MD5 0x0004 ]],
  [qw[     TLS_RSA_WITH_3DES_EDE_CBC_SHA  RSA  RSA DES_EDE3_CBC SHA1 0x000A ]],
  [qw[ TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA  RSA  DHE DES_EDE3_CBC SHA1 0x0016 ]],
  ;
my %by_name = map { ($_->name,   $_) } @cipher_suites;
my %by_code = map { ($_->number, $_) } @cipher_suites;

sub by_name {
  my ($class, $name) = @_;
  $by_name{$name} or throw Error::Simple "no such CipherSuite $name";
}

sub by_code {
  my ($class, $code) = @_;
  $by_code{0+$code} or throw Error::Simple "no such CipherSuite $code";
}






1;
