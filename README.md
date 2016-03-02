# ODUP

## Description

These scripts are an implementation of the organizational domain and use
policies (ODUP) resolution algorithm described in
[draft-deccio-dbound-organizational-domain-policy](https://tools.ietf.org/html/draft-deccio-dbound-organizational-domain-policy)
for demonstration, testing, and further development.

## Setup

In order for ODUP resolution to work properly using the included `odup.py`
script, ODUP statements must exist in the DNS.  Because this involves
modifications to the namespace controlled by many different entities, we
include scripts to make them available using local resolver configuration
instead.

The domains from Mozilla's Public Suffix List have negative policies by
definition because of their designation as "public suffixes".  Those policies
can be added to a local resolver by effectively creating local "\_odup" zones
for every name in the public suffix list:

```
$ curl -O https://publicsuffix.org/list/public_suffix_list.dat
$ mkdir odup_zones
$ python psl2odup.py public_suffix_list.dat odup_zones named.conf.odup-include localhost
```

To include these files for use in a BIND resolver, do the following:
 * Move both the `named.conf.odup-include` file and the `odup\_zones` directory
   to the directory specified by the `directory` statement in your `named.conf`
   file.
 * Add an `include` statement to your `named.conf`:
```
include "named.conf.odup-include";
```

You might also like to create additional _odup zones to test how it works
outside of the suffixes in the Public Suffix List.  The following creates a
zone with some example contexts for the _odup.example.com zone:

```
$ cat - <<EOF > db._odup.example.com
\$ORIGIN _odup.example.com.
\$TTL 604800
@ SOA a.odup.example.com. root.odup.example.com. 1 1800 900 604800 86400
  NS  a.odup.example.com.
  NS  b.odup.example.com.
sub TXT "v=odup1 +org"
sub.b.a TXT "v=odup1 +org"
no-wildcard TXT "v=odup1 -wildcardtlscert"
EOF
```

This can similarly be included in the `named.conf` of your BIND resolver, as
follows:
```
zone "_odup.example.com" {
	notify no;
	type master;
	file "db._odup.example.com";
};
```

## Compiling a Public Suffix List

The so-called ICANN names portion of the Public Suffix List can be derived from
ODUP statements in the DNS.  This is done by iteratively downloading the
"\_odup" zones from every top-level domain (TLD) in the delegated root zone.
This functionality is demonstrated in the included `odup2psl.py` script.

```
python odup2psl.py -s 127.0.0.1 root.zone > psl.dat
```

Note that this won't include TLDs not yet included in the root zone, even
though many of these are already included in Mozilla's Public Suffix List.
Also, it does not include the so-called private domains from the Public Suffix
List.  However, eventually this script will have an option to include a list of
other domains for which ODUP statements should be downloaded.

## Compiling Local ODUP Statements

As described in draft-deccio-dbound-organizational-domain-policy, ODUP
statements for the policy-negative realm can be downloaded and compiled for
local use, to avoid the overhead resulting from DNS lookups associated with
ODUP resolution.  This is demonstrated by running the `odup2psl.py` script with
the `-z` option:

```
python odup2psl.py -s 127.0.0.1 -z root.zone > db._odup
```

## ODUP Resolution

Use the `odup.py` script to perform ODUP resolution for a name.  Point the
script to your resolver using the `-s` option.  The resulting organizational
domain, policy domain, and policy (if any) will be printed to the screen.  Use
the `-d` option to show the DNS queries that are taking place.  Examples
follow.

Look up the policy for com:
```
$ python odup.py -s 127.0.0.1 com
          Domain name: com
Organizational domain: com.
        Policy domain: com.
               Policy: v=odup1 +bound +fetch:axfr:// -all
```

Look up the policy for example.com (a blank policy results in "+all"):
```
$ python odup.py -s 127.0.0.1 example.com
          Domain name: example.com
Organizational domain: example.com.
        Policy domain: example.com.
               Policy:
```

Identify the organizational domain at sub.example.com (this assumes you've set
up the _odup.example.com zone, as shown above):
```
$ python odup.py -s 127.0.0.1 sub.example.com
          Domain name: sub.example.com
Organizational domain: sub.example.com.
        Policy domain: sub.example.com.
               Policy:
```


See that there is no boundary between example.net and sub.example.net:
```
$ python odup.py -s 127.0.0.1 sub.example.net
          Domain name: sub.example.net
Organizational domain: example.net.
        Policy domain: example.net.
               Policy:
```

Use a local version of the policy-negative realm to look up the policy for
sub.example.com.  Use `-d` to show the lookups.  "(local)" means that the
information was learned from the file, rather than from DNS queries.
```
$ python odup.py -d -n .:db._odup -s 127.0.0.1 sub.example.com
com._odup./TXT: NOERROR (local): v=odup1 +bound
example.com._odup./TXT: NXDOMAIN (local)
sub._odup.example.com./TXT: NOERROR: v=odup1 +org
_odup.sub.example.com./TXT: NXDOMAIN
          Domain name: sub.example.com
Organizational domain: sub.example.com.
        Policy domain: sub.example.com.
               Policy:
```

Also use the local version of the example.com policy realm:
```
$ python odup.py -d -n .:db._odup -n example.com:db._odup.example.com -s 127.0.0.1 sub.example.com
com._odup./TXT: NOERROR (local): v=odup1 +bound
example.com._odup./TXT: NXDOMAIN (local)
sub._odup.example.com./TXT: NOERROR (local): v=odup1 +org
_odup.sub.example.com./TXT: NXDOMAIN
          Domain name: sub.example.com
Organizational domain: sub.example.com.
        Policy domain: sub.example.com.
               Policy:
```


Contrast this with the lookups performed without the local data:
```
$ python odup.py -d -s 127.0.0.1 sub.example.com
com._odup./TXT: NOERROR: v=odup1 +bound
example.com._odup./TXT: NXDOMAIN
sub._odup.example.com./TXT: NOERROR: v=odup1 +org
_odup.sub.example.com./TXT: NXDOMAIN
          Domain name: sub.example.com
Organizational domain: sub.example.com.
        Policy domain: sub.example.com.
               Policy:
```
