#
# Barnraising::ImpTLS::SSLv2Record
#


package Barnraising::ImpTLS::SSLv2Record;
use base qw( TLS::SSLv2Record );



sub is_imposter_wrapped ($) { 0 }

sub is_key_expose       ($) { 0 }

sub is_imposter_record  ($) { 0 }

sub is_new_cipher_event ($) { 0 }








1;
