#
# Mimic::Handler
#
# This simple interface represents objects which can create various
# sorts of Mimic::Message objects based on the tag.  See also
# Mimic::Message and Mimic::Registry.
#


package Mimic::Handler;

use Mimic::Message;


# Unless overridden, we don't register to handle any messages.
sub tags ($) { () }

# Unless the arguments override us, specify ourself as the handler.
sub read ($$@) {
  my ($self, $handle, %args) = @_;
  return Mimic::Message->read( $handle, Handler => $self, %args );
}

# The default method to create a message is to use
# Mimic::Message->new, but this is not terribly useful unless
# overridden.
sub create_message ($$@) {
  my ($self, $tag, @params) = @_;
  return Mimic::Message->new( $tag, @params );
}


1;
