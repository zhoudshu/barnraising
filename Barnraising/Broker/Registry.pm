#
# Barnraising::Broker::Registry
#

package Barnraising::Broker::Registry;
use base qw( Mimic::Registry );

use Barnraising::Broker::Message;
use Barnraising::Broker::Message::Hello;
use Barnraising::Broker::Message::Offer;
use Barnraising::Broker::Message::Accept;
use Barnraising::Broker::Message::Ready;
use Barnraising::Broker::Message::Inserted;


sub new ($) {
  my ($class) = @_;
  return $class->SUPER::new( Barnraising::Broker::Message::Hello,
			     Barnraising::Broker::Message::Offer,
			     Barnraising::Broker::Message::Accept,
			     Barnraising::Broker::Message::Ready,
			     Barnraising::Broker::Message::Inserted );
}



1;
