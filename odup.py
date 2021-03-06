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

import logging
import re

import dns.name, dns.resolver, dns.rdatatype, dns.zone

ODUP_VERS1 = re.compile(r'^v=odup1(\s|$)')
ORG_RE = re.compile(r'(^|\s)\+org(:\S+)?(\s|$)')
BOUND_RE = re.compile(r'(^|\s)\+bound(:(?P<labels>\d+))?(\s|$)')

class ODUPPolicyRealm(object):
    def __init__(self, origin):
        self.origin = origin
        assert self.origin.is_absolute()

        self._policies = {}

    @classmethod
    def from_file(cls, origin, filename):
        z = dns.zone.from_file(filename, dns.name.from_text('_odup', origin))

        obj = ODUPPolicyRealm(origin)
        for name, ttl, rdata in z.iterate_rdatas():
            obj.add_policy_from_rdata(name, rdata)
        obj.add_default_policy()
        obj.populate_empty_non_terminals()
        return obj

    @classmethod
    def from_aggregate_file(cls, origin, filename):
        policy_realms = {}

        z = dns.zone.from_file(filename, dns.name.from_text('_odup', origin))

        for name, ttl, rdata in z.iterate_rdatas():
            suffix = dns.name.Name(name[-1:]).derelativize(origin)
            name = dns.name.Name(name[:-1])
            if suffix not in policy_realms:
                policy_realms[suffix] = ODUPPolicyRealm(suffix)
            policy_realms[suffix].add_policy_from_rdata(name, rdata)

        for suffix in policy_realms:
            policy_realms[suffix].add_default_policy()
            policy_realms[suffix].populate_empty_non_terminals()
        return policy_realms

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.origin.to_text())

    def populate_empty_non_terminals(self):
        for name in self._policies.keys():
            if name in (dns.name.empty, dns.name.root):
                continue

            name = name.parent()
            while name not in self._policies:
                self._policies[name] = None
                try:
                    name = name.parent()
                except dns.name.NoParent:
                    break

    def add_policy_from_rdata(self, name, rdata):
        # If not type TXT, then mark that the name merely exists, but with
        # no policy
        if not isinstance(rdata, dns.rdtypes.ANY.TXT.TXT):
            self._policies[name] = None
            return

        rdata_txt = rdata.to_text().strip('"')
        # If not an ODUP policy, then mark that the name merely exists, but
        # with no policy
        if ODUP_VERS1.search(rdata_txt) is None:
            self._policies[name] = None
            return

        self._policies[name] = rdata_txt

    def add_default_policy(self):
        # add a default policy for the origin, if there isn't one already
        if self._policies.get(dns.name.empty, None) is None:
            self._policies[dns.name.empty] = ''

    def resolve(self, name, response):
        assert not name.is_absolute() or name.is_subdomain(self.origin)

        _logger = logging.getLogger(__name__)
        #_logger.debug('Enter ODUPPolicyRealm.resolve(): name: %s' % (name))

        # make sure name is relative to origin
        if name.is_absolute():
            name = name.relativize(self.origin)

        if self.origin == dns.name.root:
            origin = ''
        else:
            origin = self.origin.to_text()

        # check for org/bound directives in names in ancestry
        longest_match = None
        longest_match_boundary = None
        existing_labels = 0
        for i in range(len(name) + 1):

            if i == 0:
                test_domain = dns.name.empty
                wildcard_name = None
            else:
                test_domain = dns.name.Name(name[-i:])
                wildcard_name = dns.name.from_text('*', test_domain.parent())

            test_domain_qualified = dns.name.Name(test_domain.labels + ('_odup',) + self.origin.labels)

            policy = None
            # Name exists; check for policy
            if test_domain in self._policies:
                if i > 0:
                    existing_labels += 1
                if self._policies[test_domain] is not None:
                    _logger.debug('%s/TXT: NOERROR (local): %s' % (test_domain_qualified, self._policies[test_domain]))
                    policy = self._policies[test_domain]
                    response.add_query(test_domain_qualified, dns.rcode.NOERROR, policy)
                else:
                    # It's effectively a NODATA response
                    _logger.debug('%s/TXT: NODATA (local)' % (test_domain_qualified))
                    response.add_query(test_domain_qualified, dns.rcode.NOERROR, None)
                    pass

            # Name doesn't exist; check for wildcard
            elif wildcard_name in self._policies and self._policies[wildcard_name] is not None:
                _logger.debug('%s/TXT: NOERROR (wildcard local): %s' % (test_domain_qualified, self._policies[wildcard_name]))
                existing_labels += 1
                policy = self._policies[wildcard_name]
                response.add_query(test_domain_qualified, dns.rcode.NOERROR, policy)

            # Effective NXDOMAIN:
            # An NXDOMAIN result means that no further lookups are
            # necessary, as there is no subtree
            else:
                _logger.debug('%s/TXT: NXDOMAIN (local)' % (test_domain_qualified))
                response.add_query(test_domain_qualified, dns.rcode.NXDOMAIN, None)
                break

            if policy is not None:

                org_match = ORG_RE.search(policy)
                bound_match = BOUND_RE.search(policy)

                # Update longestMatch by giving org and bound highest
                # priority and ignoring policy statements below "bound".
                if org_match is not None or bound_match is not None or \
                        (longest_match is None or BOUND_RE.search(longest_match) is None):
                    longest_match = policy
                    longest_match_boundary = i

                # If this was a organizational domain designation,
                # then don't go any further; the organization will
                # dictate policy
                if org_match is not None:
                    break

                # If this was a boundary designation, and the answer
                # was synthesized from a wildcard, no further
                # lookups must be performed
                if bound_match is not None and \
                        bound_match.group('labels') is not None and \
                        int(bound_match.group('labels')) < i + 1:
                    break

            # Effective NODATA response
            else:
                pass

        if longest_match is not None:
            # If a policy has been found, then look for +org or +bound
            # directives, which will cause org names to be returned.
            # A +org directive indicates that the organizational domain and
            # policy are (at least) one level lower than the value of
            # longestMatchBoundary.
            if ORG_RE.search(longest_match) is not None:
                org_domain = dns.name.Name(name[-(longest_match_boundary+1):]).derelativize(self.origin)
                response.set_policy(None, org_domain, None)
                return response
            # A +bound directive indicates that the organizational domain
            # and policy are (at least) one level lower than the value of
            # longestExistingBoundary.
            if BOUND_RE.search(longest_match) is not None and \
                    existing_labels + 1 <= len(name):
                org_domain = dns.name.Name(name[-(existing_labels+1):]).derelativize(self.origin)
                response.set_policy(None, org_domain, None)
                return response

            # With no +org or +bound directives present, the orgDomain and
            # policy remain as they were looked up, and are returned with
            # the policy domain
            policy_domain = dns.name.Name(name[-(longest_match_boundary+1):]).derelativize(self.origin)
            response.set_policy(policy_domain, self.origin, longest_match)
            return response
        else:
            # Otherwise, return the policy for the orgDomain
            response.set_policy(None, self.origin, None)
            return response

class ODUPResponse(object):
    def __init__(self):
        self.queries = []
        self.policy = None
        self.policy_domain = None
        self.org_domain = None

    def add_query(self, name, rcode, rdata):
        self.queries.append((name, rcode, rdata))

    def set_policy(self, policy_domain, org_domain, policy):
        self.policy_domain = policy_domain
        self.org_domain = org_domain
        self.policy = policy

class ODUPResolver(object):
    def __init__(self, resolver=None, local_policies=None):
        if resolver is None:
            resolver = dns.resolver.Resolver()
        self._resolver = resolver
        if local_policies is None:
            local_policies = {}
        self._local_policies = local_policies

    def resolve(self, name):
        return self._resolve(name, 1, ODUPResponse())

    def _resolve(self, name, org_boundary, response):
        assert 1 <= org_boundary < len(name)

        org_domain = dns.name.Name(name[-(org_boundary+1):])

        _logger = logging.getLogger(__name__)
        #_logger.debug('Enter ODUPResolver._resolve(): name: %s; orgDomain: %s' % (name, org_domain))

        # Check local policies
        if org_domain in self._local_policies:
            self._local_policies[org_domain].resolve(name, response)
            # if an policy was actually returned, then return it
            if response.policy_domain is not None:
                return response
            # otherwise, use the hint to return the right answer
            return self._resolve(name, len(response.org_domain) - 1, response)

        subdomain_labels = len(name) - org_boundary
        longest_match = None
        longest_match_boundary = None
        existing_labels = 0
        for i in range(subdomain_labels):
            if i == 0:
                subdomain = dns.name.empty
            else:
                subdomain = dns.name.Name(name[-(org_boundary + 1 + i):-(org_boundary + 1)])
            test_domain = dns.name.Name(subdomain.labels + ('_odup',) + org_domain.labels)

            try:
                ans = self._resolver.query(test_domain, dns.rdatatype.TXT)
            except dns.resolver.NXDOMAIN:
                # An NXDOMAIN result means that no further lookups are
                # necessary, as there is no subtree
                _logger.debug('%s/TXT: NXDOMAIN' % (test_domain))
                response.add_query(test_domain, dns.rcode.NXDOMAIN, None)
                break
            except dns.resolver.NoAnswer:
                _logger.debug('%s/TXT: NODATA' % (test_domain))
                response.add_query(test_domain, dns.rcode.NOERROR, None)
                existing_labels += 1
                pass
            except dns.exception.DNSException, e:
                #TODO what is the sane default for DNS resolution errors?
                _logger.error('%s/TXT: %s' % (test_domain, e.__class__.__name__))
                response.add_query(test_domain, None, None)
                break

            else:
                if i > 0:
                    existing_labels += 1
                try:
                    policy = filter(lambda x: ODUP_VERS1.search(x.to_text().strip('"')), ans.rrset)[0].to_text().strip('"')
                except IndexError:
                    _logger.debug('%s/TXT: NOERROR (no policy)' % (test_domain))
                    response.add_query(test_domain, dns.rcode.NOERROR, None)
                else:
                    _logger.debug('%s/TXT: NOERROR: %s' % (test_domain, policy))
                    response.add_query(test_domain, dns.rcode.NOERROR, policy)

                    org_match = ORG_RE.search(policy)
                    bound_match = BOUND_RE.search(policy)

                    # Update longestMatch by giving org and bound highest
                    # priority and ignoring policy statements below "bound".
                    if org_match is not None or bound_match is not None or \
                            (longest_match is None or BOUND_RE.search(longest_match) is None):
                        longest_match = policy
                        longest_match_boundary = i

                    # If this was a organizational domain designation,
                    # then don't go any further; the organization will
                    # dictate policy
                    if org_match is not None:
                        break

                    # If this was a boundary designation, and the answer
                    # was synthesized from a wildcard, no further
                    # lookups must be performed
                    if bound_match is not None and \
                            bound_match.group('labels') is not None and \
                            int(bound_match.group('labels')) < i + 1:
                        break

        if longest_match is not None:
            # If a policy has been found, then look for +org or +bound
            # directives, which will cause resolve() to be called
            # recursively.  A +org directive indicates that the
            # organizational domain and policy are (at least) one level
            # lower than the value of longestMatchBoundary.
            if ORG_RE.search(longest_match) is not None:
                return self._resolve(name, org_boundary + longest_match_boundary, response)
            # A +bound directive indicates that the organizational domain
            # and policy are (at least) one level lower than the value of
            # longestExistingBoundary.
            if BOUND_RE.search(longest_match) is not None and \
                    org_boundary + existing_labels + 1 <= len(name) - 1:
                return self._resolve(name, org_boundary + existing_labels + 1, response)

            # With no +org or +bound directives present, the orgDomain and
            # policy remain as they were looked up, and are returned with
            # the policy domain
            response.set_policy(dns.name.Name(name[-(org_boundary + longest_match_boundary + 1):]), org_domain, longest_match)
            return response
        else:
            # Otherwise, return the policy for the orgDomain
            response.set_policy(org_domain, org_domain, "")
            return response

def usage():
    import sys
    sys.stderr.write('Usage: %s [-d] [-n <domain>:<policy_file>] [-s <server>] [-p <port>] <domainname>\n' % (sys.argv[0]))

def main():
    import sys
    import getopt
    import os.path

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'n:s:p:d')
    except getopt.error:
        usage()
        sys.exit(1)

    if len(args) != 1:
        usage()
        sys.exit(1)

    _logger = logging.getLogger(__name__)
    _logger.addHandler(logging.StreamHandler())
    _logger.setLevel(logging.WARNING)
    r = dns.resolver.Resolver()
    local_policies = {}
    for opt, arg in opts:
        if opt == '-p':
            try:
                r.port = int(arg)
            except ValueError:
                usage()
                sys.exit(1)
        elif opt == '-s':
            r.nameservers = [arg]
        elif opt == '-n':
            try:
                d, f = arg.split(':')
            except ValueError:
                usage()
                sys.exit(1)
            else:
                n = dns.name.from_text(d)
                if n == dns.name.root:
                    local_policies.update(ODUPPolicyRealm.from_aggregate_file(n, os.path.expanduser(f)))
                else:
                    local_policies[n] = ODUPPolicyRealm.from_file(n, os.path.expanduser(f))
        elif opt == '-d':
            _logger.setLevel(logging.DEBUG)

    r = ODUPResolver(resolver=r, local_policies=local_policies)
    response = r.resolve(dns.name.from_text(args[0]))
    print '          Domain name: %s' % (args[0])
    print 'Organizational domain: %s' % (response.org_domain)
    print '        Policy domain: %s' % (response.policy_domain)
    print '               Policy: %s' % (response.policy)

if __name__ == '__main__':
    main()
