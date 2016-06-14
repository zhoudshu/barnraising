#
# Mimic::Message::Simple
#


package Mimic::Message::Simple;

use base qw( Mimic::Message Mimic::Handler );


# The tag, required_params, and optional_params static methods should
# be overridden by subclasses.
sub tag             ($) { throw Error::Simple "abstract method" }
sub required_params ($) { throw Error::Simple "abstract method" }
sub optional_params ($) { throw Error::Simple "abstract method" }

sub all_params ($) {
  my ($self) = @_;
  return ($self->required_params, $self->optional_params);
}



# Implements the Mimic::Handler interface.

# The tags method may be overridden by a subclass if the subclass
# handles several tags.
sub tags ($) {
  my ($class) = @_;
  return ($class->tag);
}

sub create_message ($$@) {
  my ($class, $tag, @params) = @_;
  $class->new( @params );
}



sub new ($@) {
  my ($class, @args) = @_;
  my %args = (@args);

  for my $p ($class->required_params) {
    defined $args{$p}
      or throw Error::Simple "required parameter $_ of $class not given";
  }

  delete @args{$class->all_params};
  scalar(keys %args) == 0
    or throw Error::Simple "unrecognized parameter(s) "
      . join(", ", keys %args) . " given to $class";

  return $class->SUPER::new( $class->tag, @args );
}




1;
