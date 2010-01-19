#!/usr/bin/perl

use strict;
use warnings;
use Cache::Memcached;

my $memd = new Cache::Memcached { 'servers' => [ "127.0.0.1:11211"]  };
$memd->set(@ARGV)    if @ARGV == 2;
$memd->delete(@ARGV) if @ARGV == 1;
printf "%s => '%s'\n", $ARGV[0], $memd->get($ARGV[0]);
