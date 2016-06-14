#
# MyDNS::Zone;
#


package MyDNS::Zone;

sub new ($$$) {
  my ($class, $db, $id, $domain) = @_;
  bless { DB => $db, ID => $id, DOMAIN => $domain } => $class;
}

sub db     ($) { shift->{DB} }
sub id     ($) { shift->{ID} }
sub domain ($) { shift->{DOMAIN} }

sub default_ptr_ttl ($) { shift->db->default_ptr_ttl }
sub default_rr_ttl  ($) { shift->db->default_rr_ttl }


sub create_rr ($$$$;$$) {
  my ($self, $type, $name, $data, $aux, $ttl) = @_;
  # We use REPLACE instead of INSERT because, if a node joins
  # repeatedly, we don't want to error out.  XXX Actually, this is
  # rather bogus behavior because it does not take into account the
  # possibility of multiple users on one host joining.  Also, this is
  # definitely the wrong layer to deal with this at.  XXX Think about this more.
  $self->db->commit( "REPLACE INTO rr(zone, type, name, data, aux, ttl)
                              VALUES (?,    ?,    ?,    ?,    ?,   ?)",
		     undef,
		     $self->id, $type, $name, $data, $aux || 0,
		     $ttl || $self->default_rr_ttl );
}

sub create_ptr ($$$;$) {
  my ($self, $ip, $name, $ttl) = @_;
  $self->db->commit( "INSERT INTO ptr(ip, name, ttl) VALUES (INET_ATON(?),?,?)",
		     undef,
		     $ip, $name . "." . $self->domain,
		     $ttl || $self->default_ptr_ttl );
}







1;
