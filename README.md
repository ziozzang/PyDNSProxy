PyDNSProxy
==========

PyDNSProxy Configuration.

Author
======

Jioh L. Jung (ziozzang@gmail.com)

License
=======

This code is under License of BSD.

Functions
=========

DNS Proxy + SNI/HTTP Proxy + Very Basic Authenticate

Environment
===========

This source is working with Python 3.x + AsyncIO. you have to run in \*NIX include Linux as root permission.

ifyou want to run with Docker, buildand launch.

```
docker build -t pydnsproxy .
docker run -it --rm \
  -p 53:53/udp -p 443:443 -p 80:80 \
  -v `pwd`/dns.conf:/opt/dns.conf \
  -e "AUTH_LIST=10.2.3.4,10.9.8.7" \
  -e "AUTH_BLOCK=10.3.4.0/24,192.4.5.0/24" \
  -e "PASSPHASE=open.sesami" \
  -e "EXT_IP=1.2.3.4" -e "SELF_IP=5.6.7.8" \
  pydnsproxy
#Volume mount and Port Binding.
# you can set upstream DNS server on specific docker, use "--dns=" option.
```

Configuration
=============

on source code, there's 3 kind of configuration.

1. Authentication is on source code as IP list. if IP is in list or block, DNS and SNI proxy working. else, ith doesn't reply.
```
auth_list = ["10.2.3.4", "10.3.4.5"]  # per IP Auth.
auth_block = ["10.1.0.0/16", "10.98.76.0/24"] # Block by
```

2. or Passphase for SNIProxy Open. dns query of this Record, the gate will be open!
```
passphase = "open.the.gate.sesami"
```

3. Check the domain is really exist.
```
filter_exist_dns = True
```

on dns.conf file, you can control dns record what to reply fake one. see dns.conf file.

Matching Rules
==============

1. Matchings are sequancial.
    * Block(No Result Returned) -> Exactly Match(Exactly Same Domain only) -> Forward Match(Ask upper DNS) -> Zone Match -> RegEx Match

2. if one rule matched, ignored remains.

3. There's 3 kinds of match type. partial match(match zone), exact match and regular expression match.
    * Block : Partial Match
    * Exact Match: Exact Match
    * Forward : Partial Match
    * Zone : Partial Match
    * RegEx : RegEx.

Special Thanks
==============

* Basic SNI Proxy code from Phus Lu <phus.lu@gmail.com> https://github.com/phuslu/sniproxy/
* DNSProxy code from Crypt0s's FakeDNS. https://github.com/Crypt0s/FakeDns
