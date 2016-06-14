#
# Barnraising::ImpTLS::NewCipherEvent
#
# This class, which implements the TLS::Record interface, nevertheless
# does not represent an on-the-wire record at all.  Rather, it
# represents the event of a cipher change, which is triggered by an
# Imposter KeyExpose record.  It has no wire representation, so it
# encodes to the empty string.
#

use strict;


package Barnraising::ImpTLS::NewCipherEvent;
use base qw( Barnraising::ImpTLS::Record );

use Error;


sub new ($$) {
  my ($class, $cipher) = @_;
  bless { CIPHER => $cipher } => $class;
}

sub cipher ($) { shift->{CIPHER} }

sub _meaningless {
  throw Error::Simple
    "Internal error: this method is meaningless for NewCipherEvent.";
}
sub decode { _meaningless() }
sub content_type { _meaningless() }
sub version_major { _meaningless() }
sub version_minor { _meaningless() }
sub encrypted_payload { _meaningless() }
sub payload { _meaningless() }
sub mac_authenticator { _meaningless() }
sub decoded_payload { _meaningless() }
sub content_type_name { _meaningless() }

sub is_change_cipher_spec ($) { 0 }
sub is_alert              ($) { 0 }
sub is_handshake          ($) { 0 }
sub is_application_data   ($) { 0 }
sub is_imposter_wrapped   ($) { 0 }
sub is_key_expose         ($) { 0 }

sub is_imposter_record  ($) { 1 }
sub is_new_cipher_event ($) { 1 }

sub encode ($$) { "" }
sub to_string ($) { "0.0 new_key_event" }





1;
