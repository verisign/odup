#!/usr/bin/python

#
# Created by Casey Deccio (cdeccio@verisign.com)
#
# Copyright (c) 2015-2016, VeriSign, Inc.
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
import os
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
            tld = dns.name.from_text(name[-2])

            if tld not in n:
                n[tld] = set()
            if tld != name:
                n[tld].add(name)

def export_zone(tld, names, zonefile_dir, server_names, conffile_fh):

    filename = os.path.join(zonefile_dir, 'db._odup.%s' % (tld.to_text().rstrip('.')))
    conffile_fh.write('zone "_odup.%s" {\n' % tld.to_text())
    conffile_fh.write('\ttype master;\n')
    conffile_fh.write('\tfile "%s";\n' % filename)
    conffile_fh.write('\tallow-transfer { any; };\n')
    conffile_fh.write('};\n')

    with open(filename, 'w+') as fh:
        fh.write('$ORIGIN _odup.%s\n' % (tld.to_text()))
        fh.write('$TTL 604800\n')
        fh.write('@\tSOA\t%s root.nic.%s 1 1800 900 604800 86400\n' % (server_names[0].to_text(), tld.to_text()))
        for server_name in server_names:
            fh.write('\tNS\t%s\n' % (server_name.to_text()))
        fh.write('\tTXT\t"v=odup1 +bound +fetch:axfr:// -all"\n')

        for name in names:
            name = name.relativize(tld)
            if name[0][0].startswith('!'):
                fh.write('%s\tTXT\t"v=odup1 +org"\n' % (name.to_text().lstrip('!')))
            elif name[0] == '*':
                fh.write('%s\tTXT\t"v=odup1 +bound:%d"\n' % (name.to_text(), len(name) - 1))
            else:
                fh.write('%s\tTXT\t"v=odup1 +bound"\n' % (name.to_text()))

def usage():
    import sys
    sys.stderr.write('Usage: %s <psl_filename> <zonefile_dir> <named_conf_inc_filename> [ <server_name> ]\n' % (sys.argv[0]))

def main():
    import sys

    args = sys.argv[1:]
    if len(args) < 3:
        usage()
        sys.exit(1)

    public_suffix_file = args[0]
    zonefile_dir = args[1]
    named_conf_inc_filename = args[2]

    if len(args) > 3:
        server_name = dns.name.from_text(args[3])
    else:
        server_name = None

    icann_names = {}
    private_names = {}
    import_names(public_suffix_file, icann_names, private_names)

    with open(named_conf_inc_filename, 'w+') as fh:
        for tld in icann_names:
            if server_name is not None:
                server_names = (server_name,)
            else:
                server_names = (dns.name.Name(('a', 'odup-servers', tld[-2])),)
            export_zone(tld, icann_names[tld], zonefile_dir, server_names, fh)

if __name__ == '__main__':
    main()
