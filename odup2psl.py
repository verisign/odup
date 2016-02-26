#!/usr/bin/env python

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
import re
import socket
import sys
import urlparse

import dns.name, dns.resolver, dns.rdatatype

ODUP_VERS1 = re.compile(r'^v=odup1(\s|$)')
NEG_ALL_RE = re.compile(r'(^|\s)-all(:\S+)?(\s|$)')
ORG_RE = re.compile(r'(^|\s)\+org(:\S+)?(\s|$)')
BOUND_RE = re.compile(r'(^|\s)\+bound(:(?P<labels>\d+))?(\s|$)')
FETCH_RE = re.compile(r'(^|\s)\+fetch:(?P<uri>\S+)')

def import_tlds(f, t):
    with codecs.open(f, 'r', 'utf-8') as fh:
        for line in fh:
            cols = line.rstrip().split()
            if not cols:
                continue
            if cols[0] == '.':
                continue

            name = dns.name.from_text(cols[0])
            if len(cols) > 1 and cols[1] == 'NS':
                t.add(name)
            elif len(cols) > 2 and cols[1] == 'IN' and cols[2] == 'NS':
                t.add(name)
            elif len(cols) > 3 and cols[2] == 'IN' and cols[3] == 'NS':
                t.add(name)

def import_new_tlds(f, n, n2):
    with codecs.open(f, 'r', 'utf-8') as fh:
        for line in fh:
            if re.search('BEGIN PRIVATE', line) is not None:
                return

            line = line.rstrip()
            line = re.sub(r'//.*', '', line)
            
            if not line:
                continue
            name = dns.name.from_text(line)
            if len(name) == 2 and name not in n:
                n2.add(name)

def get_odup_zone(odup_name, resolver):
    try:
        ans = resolver.query(odup_name, dns.rdatatype.TXT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None

    try:
        policy = filter(lambda x: ODUP_VERS1.search(x.to_text().strip('"')), ans.rrset)[0].to_text().strip('"')
    except IndexError:
        return None

    fetch_match = FETCH_RE.search(policy)
    if fetch_match is None:
        return None

    uri = urlparse.urlparse(fetch_match.group('uri'))
    if uri.scheme == 'axfr':
        if uri.hostname:
            server_name = dns.name.from_text(url.hostname)
        else:
            try:
                ans = resolver.query(odup_name, dns.rdatatype.NS)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                return None
            else:
                server_name = ans.rrset[0].target

        try:
            addrinfo = socket.getaddrinfo(server_name.to_text(), 53, 0, 0, socket.IPPROTO_TCP)
        except socket.gaierror:
            return None
        else:
            server = addrinfo[0][4][0]

        return dns.query.xfr(server, odup_name)

    else:
        #TODO
        return None

def export_psl(tld, resolver):
    odup_name = dns.name.from_text('_odup', tld)
    odup_zone = get_odup_zone(odup_name, resolver)

    if odup_zone is None:
        return

    has_wildcard = False

    for ans in odup_zone:
        for rrset in ans.answer:
            if rrset.rdtype != dns.rdatatype.TXT:
                continue
            try:
                policy = filter(lambda x: ODUP_VERS1.search(x.to_text().strip('"')), rrset)[0].to_text().strip('"')
            except IndexError:
                continue

            owner = rrset.name.derelativize(tld)

            org_match = ORG_RE.search(policy)
            bound_match = BOUND_RE.search(policy)

            if owner == tld:
                if NEG_ALL_RE.search(policy) is None:
                    return
                continue

            if org_match is not None:
                sys.stdout.write(codecs.encode('!%s\n' % owner.to_unicode().rstrip('.'), 'utf8'))

            elif bound_match is not None:
                if bound_match.group('labels') is not None:
                    sys.stdout.write(codecs.encode('%s\n' % (owner.to_unicode()).rstrip('.'), 'utf8'))
                    if int(bound_match.group('labels')) == 0:
                        has_wildcard = True
                else:
                    sys.stdout.write(codecs.encode('%s\n' % (owner.to_unicode()).rstrip('.'), 'utf8'))

    # this check shouldn't be necessary, but this is to try to make the output
    # match current PSL contents, in which the TLD itself is not included if
    # there is a entry for a wildcard name directly under the TLD
    if not has_wildcard:
        sys.stdout.write(codecs.encode('%s\n' % tld.to_unicode().rstrip('.'), 'utf8'))

def aggregate_odup(tld, resolver):
    odup_name = dns.name.from_text('_odup', tld)
    odup_zone = get_odup_zone(odup_name, resolver)

    if odup_zone is None:
        return

    for ans in odup_zone:
        for rrset in ans.answer:
            if rrset.rdtype != dns.rdatatype.TXT:
                continue
            try:
                policy = filter(lambda x: ODUP_VERS1.search(x.to_text().strip('"')), rrset)[0].to_text().strip('"')
            except IndexError:
                continue

            rrset.name = rrset.name.derelativize(tld).relativize(dns.name.root)
            sys.stdout.write('%s\n' % FETCH_RE.sub('', rrset.to_text()))

def usage():
    import sys
    sys.stderr.write('Usage: %s <root_zone> [ <psl> ]\n' % (sys.argv[0]))

def main():
    import sys
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:z')
    except getopt.error:
        usage()
        sys.exit(1)

    if len(args) < 1:
        usage()
        sys.exit(1)

    opts = dict(opts)

    root_zone_file = args[0]
    if len(args) > 1:
        psl = args[1]
    else:
        psl = None
    r = dns.resolver.Resolver()
    if '-s' in opts:
        r.nameservers = [opts['-s']]

    tld_names = set()
    new_tld_names = set()
    import_tlds(root_zone_file, tld_names)
    if psl is not None:
        import_new_tlds(psl, tld_names, new_tld_names)

    if '-z' in opts:
        sys.stdout.write('$ORIGIN _odup.\n')
        sys.stdout.write('$TTL 604800\n')
        sys.stdout.write('@\tSOA\t%s root.localhost. 1 1800 900 604800 86400\n')
        sys.stdout.write('@\tNS\tlocalhost.\n')

    for tld in tld_names:
        if '-z' in opts:
            aggregate_odup(tld, r)
        else:
            export_psl(tld, r)
    for tld in new_tld_names:
        sys.stdout.write(codecs.encode('%s\n' % tld.to_unicode().rstrip('.'), 'utf8'))

if __name__ == '__main__':
    main()
