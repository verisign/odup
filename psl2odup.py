#!/usr/bin/python

#
# Created by Casey Deccio (cdeccio@verisign.com)
#
# Copyright (c) 2015, VeriSign, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import codecs
import re

import dns.name

def import_names(f, i, p):
    with codecs.open(f, 'r', 'utf-8') as fh:
        n = i
        for line in fh:
            if re.search('BEGIN PRIVATE', line) is not None:
                n = p

            line = line.rstrip()
            line = re.sub(r'//.*', '', line)
            
            if not line:
                continue
            name = dns.name.from_text(line)

            line = re.sub(r'//.*', '', line)

            n.add(name)

def usage():
    import sys
    sys.stderr.write('Usage: %s <psl_filename> <odup_ns_zone>\n' % (sys.argv[0]))

def main():
    import sys

    args = sys.argv[1:]
    if len(args) != 2:
        usage()
        sys.exit(1)

    public_suffix_file = args[0]
    zone_name = dns.name.from_text(args[1]).to_text()

    if zone_name == '.':
        sys.stderr.write('ODUP NS zone name may not be the root.\n')
        sys.exit(1)

    icann_names = set()
    private_names = set()
    import_names(public_suffix_file, icann_names, private_names)

    print '$ORIGIN _odup.'
    print '$TTL 604800'
    print '@\tSOA\ta.%s root.%s 1 1800 900 604800 86400' % (zone_name, zone_name)
    print '\tNS\ta.%s' % (zone_name)
    print '\tNS\tb.%s' % (zone_name)
    print '\tTXT\t"v=odup1 +bound -all"'

    for name in icann_names:
        if name[0][0].startswith('!'):
            print '%s\tTXT\t"v=odup1 +org"' % str(name).rstrip('.').lstrip('!')
        elif name[0] == '*':
            print '%s\tTXT\t"v=odup1 +bound:%d"' % (str(name).rstrip('.'), len(name) - 2)
        else:
            print '%s\tTXT\t"v=odup1 +bound"' % str(name).rstrip('.')

if __name__ == '__main__':
    main()
