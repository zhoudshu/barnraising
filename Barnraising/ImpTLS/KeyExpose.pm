#
# Barnraising::ImpTLS::KeyExpose
#



package Barnraising::ImpTLS::KeyExpose;



sub decode {
  my ($class, $buffer) = @_;

  length($buffer) >= 2
    or throw Error::Simple "key-expose message decode error, expected at least 2 bytes, got " . length($buffer) . " bytes";

  my ($key, $iv) = unpack( "C/a* C/a*", $buffer );

  bless {
	 KEY => $key,
	 IV  => $iv,
	} => $class;
}

sub key { shift->{KEY} }
sub iv  { shift->{IV} }


sub encode {
  my ($self) = @_;
  return pack( "C/a* C/a*", $self->key, $self->iv );
}


sub to_string {
  my ($self) = @_;
  return "key: " . unpack( "H*", $self->key )
    . ", iv: " . unpack( "H*", $self->iv );
}




1;
