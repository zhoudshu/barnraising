#
# Barnraising::Expander
#

use strict;


package Barnraising::Expander;


use Barnraising::Expander::Remote;
use Barnraising::Expander::Cache;

use Error;


sub new ($$) {
  my ($class, $spec) = @_;
  # XXX really ought to do something clever here.
  my $remote = Barnraising::Expander::Remote->new( $spec );
  return Barnraising::Expander::Cache->new( $remote );
}


sub expand ($$$) {
  my ($self, $encoding, $id) = @_;
  throw Error::Simple "abstract method";
}



1;
