#
# Mimic::Registry
#
# This class encapsulates a mapping from Mimic tags to Mimic::Message
# subclasses; its read method can be used to decode and dispatch a
# Mimic message from a stream.  Essentially, it is a simple
# Mimic::Handler multiplexor.
#


package Mimic::Registry;
use base qw( Mimic::Handler );

use Error;


sub new ($@) {
  my ($class, @handlers) = @_;
  my @map = map { my $h = $_; map {($_ => $h)} $h->tags } @handlers;
  return $class->new_from_map( @map );
}

sub new_from_map ($@) {
  my ($class, @map) = @_;
  bless {
	 MAP => {@map},
	} => $class;
}

sub tags ($) {
  my ($self) = @_;
  return keys %{$self->{MAP}};
}

sub read ($$) {
  my ($self, $handle) = @_;
  return Mimic::Message->read( $handle, Handler => $self );
}

sub create_message ($$@) {
  my ($self, $tag, @params) = @_;
  my $new_class = $self->{MAP}->{$tag};
  defined $handler
    or throw Error::Simple "protocol error, got message tag $tag, expected "
      . join " or ", $self->tags;
  return $handler->create_message( $tag, @params );
}






1;
