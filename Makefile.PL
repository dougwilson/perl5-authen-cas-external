use inc::Module::Install;

name     'Authen-CAS-External';
all_from 'lib/Authen/CAS/External.pm';
author   'Douglas Christopher Wilson <doug@somethingdoug.com>';
license  'perl';

build_requires 'Test::More';

requires 'HTML::Form'                => '5.817';
requires 'HTML::LinkExtractor'       => '0.13';
requires 'HTTP::Status'              => '5.817';
requires 'LWP::UserAgent'            => '5.819';
requires 'Moose'                     => '0.77';
requires 'Moose::Role'               => '0.89';
requires 'MooseX::StrictConstructor' => '0.08';
requires 'MooseX::Types'             => '0.08';
requires 'MooseX::Types::Moose'      => 0;
requires 'Scalar::Util'              => '1.14';
requires 'URI'                       => '1.22';
requires 'URI::QueryParam'           => 0;
requires 'namespace::clean'          => '0.04';

author_requires 'File::Spec'            => 0;
author_requires 'Pod::Coverage'         => '0.18';
author_requires 'Test::CleanNamespaces' => 0;
author_requires 'Test::DistManifest'    => 0;
author_requires 'Test::MinimumVersion'  => '0.009';
author_requires 'Test::Perl::Critic'    => 0;
author_requires 'Test::Pod'             => '1.22';
author_requires 'Test::Pod::Coverage'   => '1.08';

# Enable tests to be in multi-level directories
tests_recursive;

# Author tests in xt/
recursive_author_tests('xt');

WriteAll;

