#
# Mimic::Message::Hello
#

package Mimic::Message::Hello;
use base qw( Mimic::Message::Simple );


sub tag { "Mimic/1.0/Hello" }
sub required_params { () }
sub optional_params { qw( Suite Profile Version Role
                          Implementation Application Capabilities ) }



sub suite          ($) { shift->param( "Suite"          ) }
sub profile        ($) { shift->param( "Profile"        ) }
sub version        ($) { shift->param( "Version"        ) }
sub role           ($) { shift->param( "Role"           ) }
sub implementation ($) { shift->param( "Implementation" ) }
sub application    ($) { shift->param( "Application"    ) }
sub capabilities   ($) { shift->param_as_list( "Capabilities" ) }

sub has_capability ($$) {
  my ($self, $capability) = @_;
  my @match = grep { $_ eq $capability } $self->capabilities;
  return @match > 0;
}





1;
