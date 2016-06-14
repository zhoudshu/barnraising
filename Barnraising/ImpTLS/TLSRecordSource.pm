#
# Barnraising::ImpTLS::TLSRecordSource
#
# This class, which implements the same interface as
# TLS::RecordSource, represents the decoded record stream from an
# Imposter connection.
#

use strict;


package Barnraising::ImpTLS::TLSRecordSource;

use Barnraising::ImpTLS::RecordSource;
use Barnraising::ImpTLS::KeyExpose;
use Barnraising::ImpTLS::NewCipherEvent;
use TLS::CipherSuite;

use Barnraising::Expander;

use Error;


my $TLS_NULL_WITH_NULL_NULL
  = TLS::CipherSuite->by_name( "TLS_NULL_WITH_NULL_NULL" );


sub new ($%) {
  my ($class, %attr) = @_;

  my $expander = Barnraising::Expander->new( $attr{Expander} );

  my $imposter = Barnraising::ImpTLS::RecordSource->new( %attr );
  bless {
	 IMPOSTER     => $imposter,
	 CIPHER_SUITE => $TLS_NULL_WITH_NULL_NULL,
         EXPANDER     => $expander,
	} => $class;
}

sub imposter     ($) { shift->{IMPOSTER} }
sub cipher_suite ($) { shift->{CIPHER_SUITE} }
sub expander     ($) { shift->{EXPANDER} }

sub get ($) {
  my ($self) = @_;
  my $imp_record = $self->imposter->get();
  my $record;
  print ("ImpTLS get operator \n");
  if ( $imp_record->is_imposter_wrapped ) {
    my $encoding = $imp_record->payload_encoding;
    my $id       = $imp_record->payload_id;
    my $decoded_payload = $self->expander->expand( $encoding, $id );
    print ("ImpTLS get operator imposter_wrapped $encoding \n");
    $record =  Barnraising::ImpTLS::Record->new(
					     $imp_record->content_type & 0x7F,
					     $imp_record->version_major,
					     $imp_record->version_minor,
					     $decoded_payload,
					     $imp_record->mac_authenticator,
					    );
  } else {
    $record = $imp_record;
    print ("ImpTLS get operator not mposter_wrapped\n");
  }

  if ( $record->is_key_expose ) {
    print ("ImpTLS get operator key_expose\n");

    # Update internal state...
    # (XXX possibility of payload == undef if encrypted and we don't know key.)
    my $key_expose = Barnraising::ImpTLS::KeyExpose->decode( $record->payload );
    my $read_cipher
      = $self->cipher_suite->cipher->new( $key_expose->key, $key_expose->iv );
    $self->imposter->set_cipher( $read_cipher );
    $self->imposter->set_mac( $self->cipher_suite->mac );

    # ... and construct a magic record to notify the caller that the key
    # has changed.
    my $write_cipher
      = $self->cipher_suite->cipher->new( $key_expose->key, $key_expose->iv );
    $record = Barnraising::ImpTLS::NewCipherEvent->new( $write_cipher );

  } elsif ( $record->is_handshake ) {
    print ("ImpTLS get operator handshake\n");

    if (defined $record->payload) {
      for my $h (TLS::Handshake->decode_all( $record->payload )) {
	if ( $h->is_server_hello ) {
	  # Take note of what the cipher suite is.
	  $self->{CIPHER_SUITE} = $h->cipher_suite;
	}
      }
    }

  } elsif ( $record->is_change_cipher_spec ) {
    $self->imposter->set_cipher( undef );
    $self->imposter->set_mac   ( undef );
  }

  return $record;
}





1;
