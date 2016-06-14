#
# Barnraising::Resource
#

use strict;


package Barnraising::Resource;

use Barnraising::Broker::Client;
use Barnraising::Broker::Server;
use Barnraising::Service;



sub new ($$) {
  my ($class, $uri_string) = @_;
  my $uri = Barnraising::Resource::URI->new( $uri_string );
  bless {
	 URI => $uri,
	} => $class;
}

sub uri ($) { shift->{URI} }

sub broker_host ($) { shift->uri->host }
sub broker_port ($) { shift->uri->port }

sub domain ($) {
  my ($self) = @_;
  # zhoudshu modify for getting correct domain 
  
  # XXX this logic is temporary.  In the future, look it up in the database,
  # and if the database contains "?", check the query_form.
  # my %query = $self->uri->query_form();
  # defined( $query{domain} ) and return $query{domain};
  #my $path_domain = (split m:/:, $self->uri->path())[-1];
  my $path_domain= $self->uri->host;
  print("resource domain $path_domain \n");
  return $path_domain;
}


sub offer ($%) {
  my ($self, %attr) = @_;
  my $client = Barnraising::Broker::Client->new( $self );
  my @daemons = $client->offer( Services => $attr{Services} );
  $client->close();
  return @daemons;
}


sub handle_offer ($%) {
  my ($self, %attr) = @_;
  my ($server, $services) = ( $attr{Server}, $attr{Services} );
  for my $service ( @$services ) {
    $server->accept_service( Service  => $service,
			     Resource => $self,
			     MinionAddress => $attr{MinionAddress} );
  }
}


sub imptls_primary ($) {
  my ($self) = @_;
  # zhoudshu modify for getting correct domain 
  #my %query = $self->uri->query_form();
  #defined( $query{imptls_primary} ) and return $query{imptls_primary};
  #defined( $query{pri} ) and return $query{pri};
  return "imp." . $self->domain . ":776";
}

sub expander_primary ($) {
  my ($self) = @_;
  # zhoudshu modify for getting correct domain 
  #my %query = $self->uri->query_form();
  #defined( $query{expander_primary} ) and return $query{expander_primary};
  # XXX my god, what a kludge
  #my $pri = $self->imptls_primary();
  #$pri =~ s/:\d+$/:778/;
  #return $pri;
  return "imp." . $self->domain . ":778";
}





package Barnraising::Resource::URI;
use base qw( URI::_server );

sub default_port { 777 }

sub new {
  my ($class, $uri) = @_;
  $class->_init( $uri => "barnraising" );
}




1;
