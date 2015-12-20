#!/usr/bin/env python
#

"""
sync-addr.py: resolve given DNS names into IP addresses. The -s switch
constains answers to only ones secured by DNSSEC. The -4 switch only
returns IPv4 addresses, the -6 switch only IPv6 addresses.

An example run:

    $ sync-addr.py -s www.huque.com www.google.com
    www.huque.com: IPv4  50.116.63.23
    www.huque.com: IPv6  2600:3c03:e000:81::a
    www.google.com: No DNSSEC secured responses found

"""

import getdns, sys, getopt, os.path

def usage():
    progname = os.path.basename(sys.argv[0])
    print("""\
Usage: {0} [-s] [-4|-6] <domain1> <domain2> ...

    -s: only return DNSSEC secured answers
    -4: only return IPv4 address answers
    -6: only return IPv6 address answers

-4 and -6 are mutually exclusive. If both are specified, IPv6 wins.
""".format(progname))    
    sys.exit(1)

try:
    (options, args) = getopt.getopt(sys.argv[1:], 's46')
except getopt.GetoptError:
    usage()
else:
    if not args:
        usage()

extensions = { "return_both_v4_and_v6" : getdns.EXTENSION_TRUE }
desired_addr_type = None

for (opt, optval) in options:
    if opt == "-s":
        extensions["dnssec_return_only_secure"] = getdns.EXTENSION_TRUE
    elif opt == "-4":
        desired_addr_type = "IPv4"
    elif opt == "-6":
        desired_addr_type = "IPv6"

ctx = getdns.Context()

for hostname in args:
    try:
        results = ctx.address(name=hostname, extensions=extensions)
    except (getdns.error, e):
        print(str(e))
        break
    status = results.status
    if status == getdns.RESPSTATUS_GOOD:
        for addr in results.just_address_answers:
            addr_type = addr['address_type']
            addr_data = addr['address_data']
            if (desired_addr_type == None) or (addr_type == desired_addr_type):
                print("%s: %s  %s" % (hostname, addr_type, addr_data))
    elif status == getdns.RESPSTATUS_NO_SECURE_ANSWERS:
        print("%s: No DNSSEC secured responses found" % hostname)
    else:
        print("%s: getdns.address() returned error: %d" % (hostname, status))
