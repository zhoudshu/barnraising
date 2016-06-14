#
# Mimic::Message
#

use strict;

package Mimic::Message;
use base qw( Mimic::Handler );
use overload '""' => sub { shift->encode };

use Mimic::Error::EOF;

use Error;



sub new ($$@) {
  my ($class, $tag, @params) = @_;
  scalar(@params) % 2 == 0 or throw Error::Simple "invalid parameter list";
  bless {
	 TAG        => $tag,
	 PARAMS     => \@params,
	 PARAM_HASH => { @params },
	} => $class;
}


sub tag     ($)  { shift->{TAG} }
sub params  ($)  { keys %{ shift->{PARAM_HASH} } }

sub get     ($@) {
  my $self = shift;

  my @result = ();
  while (@_) {
    my ($name, $action) = (shift, shift);
    if ( !defined( $action ) ) {
      $action = sub { shift };
    } elsif ( ref( $action ) eq "SCALAR" ) {
      my $scalar_ref = $action;
      $action = sub { $$scalar_ref = shift; return (); };
    } elsif ( ref( $action ) eq "ARRAY" ) {
      my $array_ref = $action;
      $action = sub { @$array_ref = $self->decode_list( shift ); return (); };
    } else {
      throw Error::Simple "invalid action";
    }
    push @result, $action->( $self->{PARAM_HASH}->{$name} );
  }
  return @result;
}



# Encoding and decoding routines.

sub read ($$) {
  my ($class, $handle, %args) = @_;

  my $handler = $args{Handler} || $class;

  local ($/) = "\n";
  my $line = $handle->getline();
  defined( $line ) or throw Mimic::Error::EOF "unexpected EOF";

  $line =~ /^\s*(\S+)\s*$/
    or throw Error::Simple "protocol error, bad tag line";
  my $tag = $1;

  my @params = ();
  while (defined( $line = $handle->getline() ) && $line !~ /^$/) {
      #STDOUT->print( "read line $line .\n" );
    if ($line =~ /^([^:\s]*):\s+(.*)/s) {
      push @params, $1 => $2;
    } elsif ($line =~ /^ (.*)/s) {
      @params > 0 or throw Error::Simple "protocol error, bad parameter line";
      $params[-1] .= $1;
    } else {
      throw Error::Simple "protocol error, bad parameter line";
    }
  }

  # Remove final newlines from values.  Names won't contain
  # whitespace; empty values encode undefs.
  for (@params) { if ($_ eq "") { $_ = undef } else { s/\n$// } }

  # Pass control to the handler to create a new Message.
  return $handler->create_message( $tag, @params );
}

# Basic create_message just creates a new Mimic::Message object.
sub create_message ($$@) {
  my ($class, $tag, @params) = @_;
  return $class->new( $tag, @params );
}

# We don't handle any tags specifically, so barf if we get passed to
# Mimic::Registry.
# XXX: in the future, when Mimic::Registry supports regexp tag matching,
# return qr// to match all strings!
sub tags ($) {
  throw Error::Simple "internal error: should be overridden by subclasses";
}


sub write ($$) {
  my ($self, $handle) = @_;
  $handle->printflush( $self->encode() );
  return $self;
}

sub encode ($) {
  my ($self) = @_;
  my $output = $self->tag . "\n";
  my @params = @{ $self->{PARAMS} };
  while (@params) {
    my ($name, $value) = (shift @params, shift @params);
    $output .= "$name: ";

    ref( $value ) eq 'ARRAY' and $value = $self->encode_list( @$value );
    if (defined( $value )) {
      $value =~ /^\S/ or $output .= "\n ";
      $value =~ s/\n/\n /sg;
      $output .= $value;
    }

    $output .= "\n";
  }
  $output .= "\n";
  return $output;
}





# "Utility" routines --- ideally, these would be external, since they
# are not part of the Mimic Message format.

sub trim ($$) {
  my ($self, $value) = @_;
  return undef unless defined $value;
  $value =~ s/^\s*//s;
  $value =~ s/\s*$//s;
  return $value;
}


# Separate elements by a comma and a space.
# Escape commas by inserting an underscore after them.
# The empty list is represented by the undefined value.
sub encode_list ($@) {
  my ($self, @list) = @_;
  for (@list) { s/,([_\s])/,_$1/g }
  return @list > 0 ? join( ", ", @list ) : undef;
}

sub decode_list ($$) {
  my ($self, $value) = @_;
  defined( $value ) or return ();
  my @list = split( /,\s/, $value );
  for (@list) { s/,_/,/g }
  return @list;
}


# Filtered param accessor methods.

sub get_trimmed ($$) {
  my ($self, $name) = @_;
  return $self->trim( $self->get( $name ) );
}

sub get_as_list ($$) {
  my ($self, $name) = @_;
  my $value = $self->get( $name );
  return $self->decode_list( $value );
}

sub get_as_trimmed_list ($$) {
  my ($self, $name) = @_;
  return map { $self->trim($_) } $self->get_as_list( $name );
}







1;
