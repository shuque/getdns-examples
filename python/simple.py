#!/usr/bin/env python
#

"""
simply.py

A simple example to query a domain name and print out addresses
associated with it.
"""

import sys, getdns

hostname = sys.argv[1]

ctx = getdns.Context()
extensions = {}

results = ctx.address(name=hostname, extensions=extensions)
status = results.status

if status == getdns.RESPSTATUS_GOOD:
    for addr in results.just_address_answers:
        print(addr['address_data'])
elif results.status == getdns.RESPSTATUS_NO_NAME:
        print("%s: No such domain name" % hostname)
else:
    print("%s: getdns.address() returned error: %d" % (hostname, status))
