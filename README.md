# ODUP

## Description

These scripts are an implementation of the organizational domain and use
policies (ODUP) resolution algorithm described in
draft-deccio-dbound-organizational-domain-policy
(http://datatracker.ietf.org/doc/draft-deccio-domain-name-relationships/).

## Setup

For the most accurate results, using current behavior as a baseline, a
policy-negative realm must be created, based on Mozilla's Public Suffix List.
This can be done by running the following to create a top-level "\_odup" zone:

```
$ curl -O https://publicsuffix.org/list/public_suffix_list.dat
$ python psl2odup.py public_suffix_list.dat odup-servers.net > odup.zone
```

This zone file can be included as a zone in a BIND resolver, by adding the
following zone statement to named.conf:

```
zone "_odup" {
	notify no;
	type master;
	file "odup.zone";
};
```

You might also like to create additional _odup zones to test how it works
outside of the policy-negative realm.  The following creates a zone with some
example contexts for the _odup.example.com zone:

```
$ cat - <<EOF > odup-example.zone
\$ORIGIN _odup.example.com.
\$TTL 604800
@ SOA a.odup-servers.net. root.odup-servers.net. 1 1800 900 604800 86400
  NS  a.odup-servers.net.
  NS  b.odup-servers.net.
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
	file "odup-example.zone";
};
```

## ODUP Resolution

Use the `odup.py` script to perform ODUP resolution for a name.  Point the
script to your resolver using the `-s` option.  The resulting organizational
domain, policy domain, and policy (if any) will be printed to the screen.  Use
the `-d` option to show the DNS queries that are taking place.  Examples
follow.

Look up the policy for the root:
```
$ python odup.py -s 127.0.0.1 .
          Domain name: .
Organizational domain: .
        Policy domain: .
               Policy: v=odup1 +bound -all
```

Look up the policy for com:
```
$ python odup.py -s 127.0.0.1 com
          Domain name: com
Organizational domain: .
        Policy domain: .
               Policy: v=odup1 +bound -all
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
$ python odup.py -d -n .:odup.zone -s 127.0.0.1 sub.example.com
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
$ python odup.py -d -n .:odup.zone -n example.com:odup-example.zone -s 127.0.0.1 sub.example.com
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
