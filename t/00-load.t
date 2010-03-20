#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Catalyst::Plugin::OAuth' );
}

diag( "Testing Catalyst::Plugin::OAuth $Catalyst::Plugin::OAuth::VERSION, Perl $], $^X" );
