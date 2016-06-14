#
# Barnraising::Expander::Cache
#


package Barnraising::Expander::Cache;
# XXX formalize the interface
#use base qw( Barnraising::Expander );

use IO::File;
use Error;


my $CACHE_DIR = $ENV{MINION_CACHE_DIR} || "/var/cache/imptls";

sub set_cache_dir ($$) {
  my ($class, $dir) = @_;
  $CACHE_DIR = $dir;
}


sub new ($$) {
  my ($class, $primary) = @_;
  STDOUT->print( "Cache $primary\n " );
  -d $CACHE_DIR or throw Error::Simple "Invalid directory $CACHE_DIR";
  bless {
	 CACHE_DIR => $CACHE_DIR,
	 PRIMARY   => $primary,
	} => $class;
}

sub primary   ($) { shift->{PRIMARY} }
sub cache_dir ($) { shift->{CACHE_DIR} }


sub temp_filename ($$) {
  my ( $self, $base ) = @_;
  return "$base.tmp.$$";
}


sub expand ($$$) {
  my ($self, $encoding, $id) = @_;

  if ($encoding == 1) {

    STDOUT->print( "Literal-encoded packet received (",
		   length($id), " bytes)\n" );

    return $id;

  } elsif ($encoding == 2 || $encoding == 3) {

    my $filename
      = $self->cache_dir . "/" . $encoding . "." . unpack( "H*", $id );
    if ( -r $filename ) {
      my $f = IO::File->new( $filename, "r" )
	or throw Error::Simple "can't open cache file $filename for reading";
      local ($/) = undef;
      my $data = <$f>;

      STDOUT->print( "ID cache hit: $filename (",length($data)," bytes)\n" );

      return $data;
    }

    STDOUT->print( "ID cache miss, going to primary...  " );

    my $data = $self->primary->expand( $encoding, $id );

    # Atomically create the cache file.
    my $temp_filename = $self->temp_filename( $filename );
    my $f = IO::File->new( $temp_filename, "w" )
      or throw Error::Simple "can't open tmp file $temp_filename for writing";
    $f->print( $data );
    $f->close();

    rename $temp_filename, $filename
      or throw Error::Simple "rename $temp_filename $filename: $!";

    STDOUT->print( "got ", length($data), " bytes\n" );

    return $data;
  }

}





1;
