#!/usr/bin/perl

# $Id$
# AptPkg::System tests

BEGIN { print "1..2\n" }

use AptPkg::Config '$_config';
use AptPkg::System '$_system';

print 'not ' unless $_config->init and $_system = $_config->system;
print "ok 1\n";

print 'not ' unless $_system->label =~ /dpkg/;
print "ok 2\n";

1;
