#!/usr/bin/env python
# 
# Use stub mode with google public DNS as recursive resolvers
# to query addresses associated with a host.
#

import getdns, sys, pprint

google_public_dns = [
    {'address_data': '8.8.8.8', 'address_type': 'IPv4'},
    {'address_data': '8.8.4.4', 'address_type': 'IPv4'},
    {'address_data': '2001:4860:4860::8888', 'address_type': 'IPv6'},
    {'address_data': '2001:4860:4860::8844', 'address_type': 'IPv6'},
]

hostname = sys.argv[1]

ctx = getdns.Context()
ctx.resolution_type = getdns.RESOLUTION_STUB
ctx.upstream_recursive_servers = google_public_dns
extensions = {}

try:
    results = ctx.address(name=hostname, extensions=extensions)
except (getdns.error, e):
    print(str(e))
    sys.exit(1)

if results.status == getdns.RESPSTATUS_GOOD:
    for addr in results.just_address_answers:
        print(addr["address_data"])
elif results.status == getdns.RESPSTATUS_NO_NAME:
    print("%s: No such domain name" % hostname)
else:
    print("getdns.address() returned an error: %d" % results.status)

