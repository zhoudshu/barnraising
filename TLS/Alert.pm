package TLS::Alert;


use Error;


sub decode {
  my ($class, $buffer) = @_;

  length( $buffer ) == 2
    or throw Error::Simple "alert message decode error, expected 2 bytes, got "
      . length($buffer) . " bytes";

  my ($level, $description) = unpack "CC", $buffer;

  bless {
	 LEVEL => $level,
	 DESCRIPTION => $description,
	} => $class;
}

sub level       { shift->{LEVEL} }
sub description { shift->{DESCRIPTION} }

sub level_name {
  my $level = shift->level;
  return
    $level == 1 ? "warning"
      : $level == 2 ? "fatal"
	: throw Error::Simple "invalid AlertLevel $level";
}
sub description_name {
  my $desc = shift->description;
  my $name = {
	      0  => "close_notify",
	      41 => "no_certificate",
	     }->{$desc};
  defined $name or throw Error::Simple "invalid AlertDescription $desc";
  return $name;
}


sub encode {
  my ($self) = @_;
  return pack "CC", $self->level, $self->description;
}

sub to_string {
  my ($self) = @_;
  return $self->level_name . ": " . $self->description_name;
}



1;
