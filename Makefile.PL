use inc::Module::Install;

name     'Authen-CAS-External';
all_from 'lib/Authen/CAS/External.pm';
author   'Douglas Christopher Wilson <doug@somethingdoug.com>';
license  'perl';

build_requires 'Test::More';

requires 'Authen::CAS::Client' => '0.03';
requires 'WWW::Mechanize'      => '1.54';

auto_install;

WriteAll;

