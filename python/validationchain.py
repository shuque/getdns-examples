#!/usr/bin/env python
#

import getdns, pprint, sys, time
import dns.rdatatype

hostname = sys.argv[1]

extensions = {
    "dnssec_return_validation_chain" : getdns.EXTENSION_TRUE,
}

ctx = getdns.Context()

results = ctx.address(name=hostname, extensions=extensions)

if results.status == getdns.RESPSTATUS_GOOD:
    print("Validation Chain:")
    for x in results.validation_chain:
        if x['type'] == 46:
            print("\t%s RRSIG(%s)" % 
                  (x['name'], 
                   dns.rdatatype.to_text(x['rdata']['type_covered'])))
        else:
            print("\t%s %s" % (x['name'], dns.rdatatype.to_text(x['type'])))
    print('\nFull Response Dictionary:')
    pprint.pprint(results.validation_chain)
else:
    print("getdns.address() returned an error: %d" % results.status)

