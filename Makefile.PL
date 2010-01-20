use inc::Module::Install;

name     'Authen-CAS-External';
all_from 'lib/Authen/CAS/External.pm';
author   'Douglas Christopher Wilson <doug@somethingdoug.com>';
license  'perl';

build_requires 'Test::More';

requires 'HTML::Form'                => '5.817';
requires 'HTML::TokeParser'          => '3.00';
requires 'HTTP::Status'              => '5.817';
requires 'LWP::UserAgent'            => '5.819';
requires 'Moose'                     => '0.89';
requires 'Moose::Role'               => '0.89';
requires 'MooseX::StrictConstructor' => '0.08';
requires 'MooseX::Types'             => '0.08';
requires 'MooseX::Types::Moose'      => 0;
requires 'Scalar::Util'              => '1.14';
requires 'URI'                       => '1.22';
requires 'URI::QueryParam'           => 0;
requires 'namespace::clean'          => '0.04';

# Requirements for the tests in xt/
author_requires
	'Test::More'     => 0,
	'Test::Requires' => 0.02;

# Enable tests to be in multi-level directories
tests_recursive;

# Author tests in xt/
recursive_author_tests('xt');

WriteAll;

