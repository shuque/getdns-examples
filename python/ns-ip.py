#!/usr/bin/env python
#

"""
Lookup an NS record and printout all the hostnames and associated IP
addresses of the listed nameservers.
"""

import getdns, pprint, sys, os.path

extensions = {}


def usage():
    progname = os.path.basename(sys.argv[0])
    print("""Usage: {0} <zone>

where <zone> is a DNS zone (domain).
""".format(progname))
    sys.exit(1)


def get_ip(ctx, qname):
    iplist = []
    results = ctx.address(name=qname, extensions=extensions)
    if results.status == getdns.RESPSTATUS_GOOD:
        for addr in results.just_address_answers:
            iplist.append(addr['address_data'])
    else:
        print("getdns.address() returned an error: %d" % results.status)
    return iplist


if __name__ == '__main__':

    if len(sys.argv) != 2:
        usage()

    qname = sys.argv[1]

    ctx = getdns.Context()
    results = ctx.general(name=qname, request_type=getdns.RRTYPE_NS)
    status = results.status

    hostlist = []
    if status == getdns.RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            answers = reply['answer']
            for answer in answers:
                if answer['type'] == getdns.RRTYPE_NS:
                    iplist = get_ip(ctx, answer['rdata']['nsdname'])
                    for ip in iplist:
                        hostlist.append( (answer['rdata']['nsdname'], ip) )
    elif status == getdns.RESPSTATUS_NO_NAME:
        print("%s: no such DNS zone" % qname)
    elif status == getdns.RESPSTATUS_ALL_TIMEOUT:
        print("%s, NS: query timed out" % qname)
    else:
        print("%s, %s: unknown return code: %d" % status)

    # Print out each NS server name and IP address
    for (nsdname, addr) in sorted(hostlist):
        print("%s %s" % (nsdname, addr))

