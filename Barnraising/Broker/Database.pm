#
# Barnraising::Broker::Database
#


package Barnraising::Broker::Database;

use strict;

use MyDNS::Database;

use DBI;
use Error;


sub new ($%) {
  my ($class, %attr) = @_;

  my $dbh = $attr{DBI};
  $class->verify_consistency( $dbh );

  my $self = bless {
		    DBH   => $dbh,
		    MYDNS => undef,
		   } => $class;

  # XXX a memory leak (cycle) is created here; can we elegantly avoid it?
  $self->{MYDNS} = MyDNS::Database->new( DB  => $self,
					 PID => $attr{MyDNS_PID} );

  return $self;
}

sub dbh   ($) { shift->{DBH} }
sub mydns ($) { shift->{MYDNS} }

sub do ($@) {
  my ($self, @command) = @_;
  return $self->dbh->do( @command );
}

sub commit ($@) {
  my ($self, @command) = @_;

  # If there were arguments, "do" them as an SQL statement.
  @command and $self->do( @command );

  # Commit to the backing store.
  return $self->dbh->commit();
}

sub prepare ($$) {
  my ($self, $command) = @_;
  return $self->dbh->prepare( $command );
}




# Puts the backend databae in a completely "clean" state.
sub reset ($) {
  my ($self) = @_;
  $self->do(     "DROP TABLE IF EXISTS resources" );
  $self->commit( "CREATE TABLE resources ( id        INT UNSIGNED NOT NULL,
                                           uri       BLOB NOT NULL,
                                           UNIQUE KEY (uri) )" );
}


# Verify internal consistency of the backend database.
sub verify_consistency ($$) {
  my ($class, $dbh) = @_;
  # (no requirements)
}


sub lookup_resource ($$) {
  my ($self, $uri) = @_;
  $uri = URI->new( $uri, "barnraising" );
  return Barnraising::Broker::Database::Resource->lookup( $self, $uri );
}

sub lookup_resource_id ($$) {
  my ($self, $uri) = @_;
  my $sth = $self->prepare( "SELECT id FROM resources WHERE uri = ?" );
  $sth->execute( $uri );
  my ($id) = $sth->fetchrow_array();
  defined( $id )
    or throw Error::Simple "no such resource $uri in resources table";
  return $id;
}




package Barnraising::Broker::Database::Resource;
use base qw( Barnraising::Resource );


sub new ($$$$) {
  my ($class, $db, $id, $uri) = @_;
  bless {
	 DB => $db,
	 ID => $id,
	 URI => $uri,
	} => $class;
}

sub db  ($) { shift->{DB} }
sub id  ($) { shift->{ID} }
sub uri ($) { shift->{URI} }


sub lookup ($$) {
  my ($class, $db, $uri) = @_;
  my $id = $db->lookup_resource_id( $uri->path );
  return $class->new( $db, $id, $uri );
}




sub offer ($$\@) {
  my ($self, $minion_address, $service_tags) = @_;
  my @bindings = ();
  # XXX CTL In the future, we may desire more flexibility, but for now,
  # there's no good reason not to hardcode a short list.
  if (grep { /^ImpTLS$/ } @$service_tags) {
    push @bindings, $self->offer_imptls( $minion_address );
  }
  return @bindings;
}

sub offer_imptls ($$) {
  my ($self, $minion_address) = @_;
  return Barnraising::Broker::Database::Service::ImpTLS
    -> new( $self->db, $self, $minion_address);
}




package Barnraising::Broker::Database::Service::ImpTLS;

sub new {
  my ($class, $db, $resource, $minion_address) = @_;
  bless {
	 DB             => $db,
	 RESOURCE       => $resource,
	 MINION_ADDRESS => $minion_address,
	} => $class;
}




1;
