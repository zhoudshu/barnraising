package TLS::Handshake;


use TLS::CipherSuite;

use Error;




sub decode_all {
  my ($class, $buffer) = @_;
  my @handshakes = ();
  while ($buffer ne "") {
    my ($handshake, $rest) = $class->decode( $buffer );
    $buffer = $rest;
    push @handshakes, $handshake;
  }
  return @handshakes;
}



sub decode {
  my ($class, $buffer) = @_;

  my $header = substr($buffer, 0, 4, "");
  length($header) == 4
    or throw Error::Simple "short handshake header: expected 4 bytes, but got " . length($header) . " bytes";

  my ($msg_type, $length_hi, $length_lo) = unpack( "CCn", $header );
  my $length = ($length_hi << 16) + $length_lo;

  my $body = substr($buffer, 0, $length, "");
  my $self = $class->decode_body( $msg_type, $body );

  return ($self, $buffer);
}

sub decode_body {
  my ($class, $msg_type, $body) = @_;
  my $subclass = {
		  0  => TLS::Handshake::HelloRequest,
		  1  => TLS::Handshake::ClientHello,
		  2  => TLS::Handshake::ServerHello,
		  11 => TLS::Handshake::Certificate,
		  12 => TLS::Handshake::ServerKeyExchange,
		  13 => TLS::Handshake::CertificateRequest,
		  14 => TLS::Handshake::ServerHelloDone,
		  15 => TLS::Handshake::CertificateVerify,
		  16 => TLS::Handshake::ClientKeyExchange,
		  20 => TLS::Handshake::Finished,
		 }->{$msg_type};
  defined $subclass
    or throw Error::Simple "error decoding handshake: invalid HandshakeType $msg_type";

  return $subclass->decode_body( $msg_type, $body );
}



sub encode {
  my ($self) = @_;
  my $msg_type = $self->msg_type();
  my $body = $self->encode_body();
  my $length = length $body;
  return pack("CCn", $msg_type, $length >> 16, $length & 0xFFFF) . $body;
}


sub msg_type {
  my ($self) = @_;
  throw Error::Simple "abstract method";
}

sub encode_body {
  my ($self) = @_;
  throw Error::Simple "abstract method";
}

sub to_string {
  my ($self) = @_;
  throw Error::Simple "abstract method";
}

sub is_hello_request { 0 }
sub is_client_hello { 0 }
sub is_server_hello { 0 }
sub is_certificate { 0 }
sub is_server_key_exchange { 0 }
sub is_certificate_request { 0 }
sub is_server_hello_done { 0 }
sub is_certificate_verify { 0 }
sub is_client_key_exchange { 0 }
sub is_finished { 0 }






package TLS::Handshake::Generic;
use base qw( TLS::Handshake );

sub decode_body {
  my ($class, $msg_type, $body) = @_;
  bless { MSG_TYPE => $msg_type, BODY => $body } => $class;
}

sub msg_type    { shift->{MSG_TYPE} }
sub body        { shift->{BODY} }


sub encode_body { shift->body }

sub to_string {
  my ($self) = @_;
  my $type = ref $self;
  $type =~ s/^TLS::Handshake:://;
  return $type . ": " . unpack("H*", $self->body);
}





package TLS::Handshake::HelloRequest;
use base qw( TLS::Handshake::Generic );
sub is_hello_request { 1 }



package TLS::Handshake::ClientHello;
use base qw( TLS::Handshake );
sub is_client_hello { 1 }

sub decode_body {
  my ($class, $msg_type, $body) = @_;

  my ($client_version_major, $client_version_minor, $random, $session_id,
      $cipher_suites, @compression_methods)
    = unpack( "C C a32 C/a* n/a* C/C*", $body );

  length($cipher_suites) % 2 == 0
    or throw Error::Simple "decoding ClientHello: bad cipher_suites length";
  my @cipher_suites = unpack("n*", $cipher_suites);

  length($session_id) <= 32
    or throw Error::Simple "decoding ClientHello: invalid length specified for SessionID: expected 0..32, got " . length($session_id);
  @cipher_suites > 1
    or throw Error::Simple "decoding ClientHello: not enough cipher-suites";
  @compression_methods > 0
    or throw Error::Simple "decoding ClientHello: must have at least one compression method";

  bless {
	 MSG_TYPE             => $msg_type,
	 CLIENT_VERSION_MAJOR => $client_version_major,
	 CLIENT_VERSION_MINOR => $client_version_minor,
	 RANDOM               => $random,
	 SESSION_ID           => $session_id,
	 CIPHER_SUITES        => \@cipher_suites,
	 COMPRESSION_METHODS  => \@compression_methods,
	} => $class;
}

sub msg_type             { shift->{MSG_TYPE} }
sub client_version_major { shift->{CLIENT_VERSION_MAJOR} }
sub client_version_minor { shift->{CLIENT_VERSION_MINOR} }
sub random               { shift->{RANDOM} }
sub session_id           { shift->{SESSION_ID} }
sub cipher_suites        { @{ shift->{CIPHER_SUITES} } }
sub compression_methods  { @{ shift->{COMPRESSION_METHODS} } }

sub encode_body {
  my ($self) = @_;
  throw Error::Simple "NYI";
}

sub to_string {
  my ($self) = @_;
  my $s = "ClientHello:\n";
  $s .= "    Client version: " . $self->client_version_major
    . "." . $self->client_version_minor . "\n";
  $s .= "    Random: " . unpack( "H*", $self->random ) . "\n";
  $s .= "    Session ID: " . unpack( "H*", $self->session_id ) . "\n";
  $s .= "    Cipher suites:\n";
  for $cs ($self->cipher_suites) {
    $s .= "      " . sprintf("0x%04X", $cs) . "\n";
  }
  $s .= "    Compression methods:\n";
  for $cm ($self->compression_methods) {
    $s .= "      " . sprintf("0x%02X", $cm) . "\n";
  }
  return $s;
}


package TLS::Handshake::ServerHello;
use base qw( TLS::Handshake );
sub is_server_hello { 1 }

sub decode_body {
  my ($class, $msg_type, $body) = @_;

  my ($server_version_major, $server_version_minor, $random, $session_id,
      $cipher_suite_number, $compression_method)
    = unpack( "C C a32 C/a* n C", $body );

  length($session_id) <= 32
    or throw Error::Simple "decoding ServerHello: invalid length specified for SessionID: expected 0..32, got " . length($session_id);

  my $cipher_suite = TLS::CipherSuite->by_code( $cipher_suite_number );

  bless {
	 MSG_TYPE             => $msg_type,
	 SERVER_VERSION_MAJOR => $server_version_major,
	 SERVER_VERSION_MINOR => $server_version_minor,
	 RANDOM               => $random,
	 SESSION_ID           => $session_id,
	 CIPHER_SUITE         => $cipher_suite,
	 COMPRESSION_METHOD   => $compression_method,
	} => $class;
}

sub msg_type             { shift->{MSG_TYPE} }
sub server_version_major { shift->{SERVER_VERSION_MAJOR} }
sub server_version_minor { shift->{SERVER_VERSION_MINOR} }
sub random               { shift->{RANDOM} }
sub session_id           { shift->{SESSION_ID} }
sub cipher_suite         { shift->{CIPHER_SUITE} }
sub compression_method   { shift->{COMPRESSION_METHOD} }

sub encode_body {
  my ($self) = @_;
  throw Error::Simple "NYI";
}

sub to_string {
  my ($self) = @_;
  my $s = "ServerHello:\n";
  $s .= "    Server version: " . $self->server_version_major
    . "." . $self->server_version_minor . "\n";
  $s .= "    Random: " . unpack( "H*", $self->random ) . "\n";
  $s .= "    Session ID: " . unpack( "H*", $self->session_id ) . "\n";
  $s .= "    Cipher suite: " . $self->cipher_suite->to_string . "\n";
  $s .= "    Compression method: "
    . sprintf("0x%02X", $self->compression_method) . "\n";
  return $s;
}



package TLS::Handshake::Certificate;
use base qw( TLS::Handshake );
sub is_certificate { 0 }

sub decode_body {
  my ($class, $msg_type, $body) = @_;

  # Kludgey unpack to strip off a uint24 from the front.
  my $length = unpack( "N", "\0" . substr($body, 0, 3, "") );
  $length == length($body)
    or throw Error::Simple "bad length inside Certificate handshake message";

  my @certificates = ();
  while ($body ne "") {
    # Strip off a uint24 from the front.
    my $length = unpack( "N", "\0" . substr($body, 0, 3, "") );
    my $cert = substr($body, 0, $length, "");
    $length == length($cert)
      or throw Error::Simple "bad cert length inside Certificate handshake message";
    push @certificates, $cert;
  }

  bless {
	 MSG_TYPE => $msg_type,
	 CERTIFICATES => \@certificates,
	} => $class;
}

sub msg_type { shift->{MSG_TYPE} }
sub certificates { @{ shift->{CERTIFICATES} } }

sub encode_body {
  my ($self) = @_;
  throw Error::Simple "NYI";
}

sub to_string {
  my ($self) = @_;
  return "Certificate: (" . scalar($self->certificates) . " certs)";
}




package TLS::Handshake::ServerKeyExchange;
use base qw( TLS::Handshake::Generic );
sub is_server_key_exchange { 1 }


package TLS::Handshake::CertificateRequest;
use base qw( TLS::Handshake::Generic );
sub is_certificate_request { 1 }


package TLS::Handshake::ServerHelloDone;
use base qw( TLS::Handshake );
sub is_server_hello_done { 1 }

sub decode_body {
  my ($class, $msg_type, $body) = @_;
  length($body) == 0
    or throw Error::Simple "ServerHelloDone body not empty as required";
  bless { MSG_TYPE => $msg_type } => $class;
}

sub msg_type { shift->{MSG_TYPE} }
sub encode_body { return ""; }
sub to_string { return "ServerHelloDone"; }



package TLS::Handshake::CertificateVerify;
use base qw( TLS::Handshake::Generic );
sub is_certificate_verify { 1 }



package TLS::Handshake::ClientKeyExchange;
use base qw( TLS::Handshake::Generic );
sub is_client_key_exchange { 1 }




package TLS::Handshake::Finished;
use base qw( TLS::Handshake::Generic );
sub is_finished { 1 }





1;
