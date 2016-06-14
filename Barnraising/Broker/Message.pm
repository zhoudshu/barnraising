#
# Barnraising::Broker::Message
#


use strict;


package Barnraising::Broker::Message::Hello;
use base qw( Mimic::Message::Hello );

sub new ($$) {
  my ($class, @params) = @_;
  my %params = (@params);
  my $capabilities
    = defined( $params{Role} ) && !defined( $params{Capabilities} )
      ? ["Barnraising/Broker/1.0/$params{Role}"] : undef;

  $class->SUPER::new(
		     Suite          => "Barnraising",
		     Profile        => "Broker",
		     Version        => "1.0",
		     # Role           => undef,
		     Implementation => undef,
		     Application    => undef,
		     $capabilities ? (Capabilities   => $capabilities) : (),
		     @params
		    );
}

sub default_suite   ($@) { "Barnraising" }
sub default_profile ($@) { "Broker" }
sub default_version ($@) { "1.0 " }
sub default_capabilities ($@) {
  my ($class, %params) = @_;
  return defined( $params{Role} )
    ? ["Barnraising/Broker/1.0/$params{Role}"]
      : undef;
}

# Called when reading a message from a socket.
# We want to bypass all the defaults assigned by the new() method.
sub create_message ($$@) {
  my ($class, $tag, @params) = @_;
  $class->SUPER::new( @params );
}







package Barnraising::Broker::Message::Offer;
use base qw( Mimic::Message::Simple );

sub tag             ($) { "Barnraising/Broker/1.0/Offer" }
sub required_params ($) { qw( Resource Services ) }
sub optional_params ($) { qw( ) }





package Barnraising::Broker::Message::Accept;
use base qw( Mimic::Message::Simple );

sub tag             ($) { "Barnraising/Broker/1.0/Accept" }
sub required_params ($) { qw( Service ) }
sub optional_params ($) { qw( ) }




1;
