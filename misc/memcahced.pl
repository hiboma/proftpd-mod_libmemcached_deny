#!/usr/bin/perl

use strict;
use warnings;
use Cache::Memcached;

my $memd = new Cache::Memcached { 'servers' => [ "127.0.0.1:11211"]  };
my $key = shift;
$memd->set($key, join "\t", @ARGV) if @ARGV != 0;
$memd->delete($key)               if @ARGV == 0;
printf "%s => '%s'\n", $key, $memd->get($key);
