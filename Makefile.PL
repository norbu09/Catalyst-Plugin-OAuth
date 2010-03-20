use inc::Module::Install;

name     'Catalyst-Plugin-OAuth';
all_from 'lib/Catalyst/Plugin/OAuth.pm';
author   q{Lenz Gschwendtner <norbu09@cpan.org>};
license  'perl';

requires 'OAuth::Lite';
requires 'Class::Accessor::Fast';
requires 'Class::ErrorHandler';
requires 'List::MoreUtils';

build_requires 'Test::More';

auto_install;

WriteAll;

