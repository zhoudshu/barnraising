#
# MyDNS::Database
#

package MyDNS::Database;

use MyDNS::Zone;

use DBI;
use Error qw( :try );


sub new ($%) {
  my ($class, %attr) = @_;
  bless {
	 DB        => $attr{DB},
	 PID       => $attr{PID}
	} => $class;
}

sub db  ($) { shift->{DB} }
sub pid ($) { shift->{PID} }

sub do ($@) {
  my ($self, @command) = @_;
  return $self->db->do( @command );
}

sub commit ($@) {
  my ($self, @command) = @_;

  $self->db->commit( @command );

  # Make mydns flush its cache.
  $self->pid and kill HUP => $self->pid;

  return $rc;
}

sub prepare ($$) {
  my ($self, $command) = @_;
  return $self->db->prepare( $command );
}




sub default_ttl      ($) { 300 }
sub default_soa_ttl  ($) { shift->default_ttl }
sub default_ptr_ttl  ($) { shift->default_ttl }
sub default_rr_ttl   ($) { shift->default_ttl }


sub reset ($) {
  my ($self) = @_;
  $self->do( "DROP TABLE IF EXISTS rr" );
  $self->do( "DROP TABLE IF EXISTS ptr" );
  $self->do( "DROP TABLE IF EXISTS soa" );

#  my $commands = `/usr/sbin/mydns --create-tables 2>/dev/null`;
  my $commands = <<'___END_OF_SQL___';
-- 
--  Table layouts for mydns 0.9.3 (Nov 2002)
--  Copyright (C) 2002 Don Moore
-- 
--  You might create these tables with a command like:
-- 
--    $ mydns --create-tables | mysql -hHOST -p -uUSER DATABASE
-- 
-- 

-- 
--  Table structure for table 'soa' (zones of authority)
-- 

CREATE TABLE IF NOT EXISTS soa (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  origin     CHAR(78) NOT NULL,
  ns         CHAR(255) NOT NULL,
  mbox       CHAR(255) NOT NULL,
  serial     INT UNSIGNED NOT NULL default '1',
  refresh    INT UNSIGNED NOT NULL default '28800',
  retry      INT UNSIGNED NOT NULL default '7200',
  expire     INT UNSIGNED NOT NULL default '604800',
  minimum    INT UNSIGNED NOT NULL default '86400',
  ttl        INT UNSIGNED NOT NULL default '86400',
  UNIQUE KEY (origin)
) TYPE=MyISAM;


-- 
--  Table structure for table 'rr' (resource records)
-- 

CREATE TABLE IF NOT EXISTS rr (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  zone       INT UNSIGNED NOT NULL,
  name       CHAR(63) NOT NULL,
  type       ENUM('A','AAAA','CNAME','MX','NS','TXT'),
  data       CHAR(255) NOT NULL,
  aux        INT UNSIGNED NOT NULL,
  ttl        INT UNSIGNED NOT NULL default '86400',
  UNIQUE KEY rr (zone,name,type,data)
) TYPE=MyISAM;


-- 
--  Table structure for table 'ptr'
-- 

CREATE TABLE IF NOT EXISTS ptr (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ip         INT UNSIGNED NOT NULL,
  name       CHAR(255) NOT NULL,
  ttl        INT UNSIGNED NOT NULL default '86400',
  UNIQUE KEY (ip)
) TYPE=MyISAM;


___END_OF_SQL___

  $commands =~ s/^--.*$//mg;
  for my $cmd (split /;/, $commands) {
    next if $cmd !~ /\S/;
    $self->do( $cmd );
  }

  $self->commit();
}

sub canonicalize_domain ($$) {
  my ($self, $domain) = @_;
  # Append a dot to the end if there isn't any.
  $domain =~ s/\.?$/./;
  return $domain;
}

sub create_zone ($$$) {
  my ($self, $domain, $admin_email) = @_;
  $domain = $self->canonicalize_domain( $domain );
  $self->commit( "INSERT INTO soa (origin, ns, mbox, serial,
                                   refresh, retry, expire, minimum, ttl)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		 undef,
		 $domain, "", $admin_email || "", time(),
		 0, 0, 0, 0, $self->default_soa_ttl );
  return $self->lookup_zone( $domain );
}

sub lookup_zone ($$) {
  my ($self, $domain) = @_;
  $domain = $self->canonicalize_domain( $domain );
  my $sth = $self->prepare( "SELECT id FROM soa WHERE origin = ?" );
  $sth->execute( $domain );
  my ($id) = $sth->fetchrow_array();
  defined( $id ) or throw Error::Simple "no such domain $domain in soa table";
  return MyDNS::Zone->new( $self, $id, $domain );
}




1;
