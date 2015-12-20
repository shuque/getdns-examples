#!/usr/bin/env python
#

"""
dumpdict.py

Dump response dictionary. Doesn't work in latest version of python
bindings due to changes in the response objects. Will update later.
"""

import sys, getdns, pprint

qname = sys.argv[1]
try:
    qtype = int(sys.argv[2])
except:
    qtype = 1                          # A record

ctx = getdns.Context()
extensions = {}
#extensions = { "dnssec_return_status": getdns.EXTENSION_TRUE }
#extensions = { "dnssec_return_only_secure": getdns.EXTENSION_TRUE }

results = ctx.general(name=qname, request_type=qtype,
                      extensions=extensions)
status = results.status

if status == getdns.RESPSTATUS_GOOD:
    pprint.pprint(results)
else:
    print("%s, %d: getdns.address() returned error: %d" %
          (qname, qtype, status))
    print('')
    pprint.pprint(results)
