#!/usr/bin/env python
#

from getdns import *
import pprint

ctx = Context()
ctx.resolution_type = RESOLUTION_STUB

ext = { "dnssec_return_only_secure": EXTENSION_TRUE }
res = ctx.general('_443._tcp.getdnsapi.net', RRTYPE_TLSA, ext)

if res.status == RESPSTATUS_ALL_BOGUS_ANSWERS:
    print("Got bogus answer. Switching to full recursion ..")
    ctx.resolution_type = RESOLUTION_RECURSING
    res = ctx.general('_443._tcp.getdnsapi.net', RRTYPE_TLSA, ext)

if res.status == RESPSTATUS_GOOD: # Process TLSA Rrs
    # do stuff here
    pprint.pprint(res)

