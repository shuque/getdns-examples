#!/usr/bin/env python

import getdns, sys

hostname = sys.argv[1]

ctx = getdns.Context()
ctx.resolution_type = getdns.RESOLUTION_STUB
extensions = {}

results = ctx.address(name=hostname, extensions=extensions)

if results.status == getdns.RESPSTATUS_GOOD:
    for addr in results.just_address_answers:
        print(addr["address_data"])
elif results.status == getdns.RESPSTATUS_NO_NAME:
        print("%s: No such domain name" % hostname)
else:
    print("getdns.address() returned an error: %d" % results.status)

