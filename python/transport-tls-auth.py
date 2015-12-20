#!/usr/bin/env python

import getdns, sys
import pprint

server   = "185.49.141.38"

args = sys.argv[1:]
if args[0].startswith('@'):
    server = args[0][1:]
    qname = args[1]
else:
    qname = args[0]

recursives = [
    {
        'address_data': server, 
        'address_type': 'IPv4',
        'tls_auth_name': 'www.getdnsapi.net'       # does this work?
    },
]

recursives = [
    { 'address_data': server, 'address_type': 'IPv4' },
]

ctx = getdns.Context()
ctx.resolution_type = getdns.RESOLUTION_STUB
ctx.upstream_recursive_servers = recursives
ctx.dns_transport_list = [ getdns.TRANSPORT_TLS ]
ctx.tls_authentication = getdns.AUTHENTICATION_HOSTNAME
extensions = {}

pprint.pprint(ctx.get_api_information())
sys.exit(0)

results = ctx.address(name=qname, extensions=extensions)

if results.status == getdns.RESPSTATUS_GOOD:
    for addr in results.just_address_answers:
        print addr["address_data"]
else:
    print "getdns.address() returned an error: %d" % results.status

