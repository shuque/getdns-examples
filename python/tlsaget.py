#!/usr/bin/env python
#

"""
tlsaget.py

Get (print) TLSA records for a hostname or service, resolving MX and/or SRV
records appropriately if needed.

Shumon Huque <shuque@gmail.com>
"""

import getdns, sys, getopt, os.path, pprint
from binascii import hexlify
import dns.rdatatype, dns.rdataclass


# Options class
class Opts:
    port = 443
    transport = 'tcp'
    service = None
    ext_secure = { "dnssec_return_only_secure" : getdns.EXTENSION_TRUE }


def usage():
    """Print usage string and exit"""
    progname = os.path.basename(sys.argv[0])
    print("""\
Usage: {0} [Options] <domain> [<port>] [<transport>]

Options:
    -s service_name:     lookup relevant service, resolving MX/SRV if needed
                         (Supported: smtp, xmpp-client, xmpp-server)
    -u:                  lookup without DNSSEC validation
""".format(progname))    
    sys.exit(1)


def parse_args(argv):
    """Parse command line arguments"""
    try:
        (options, args) = getopt.getopt(argv[1:], 's:u')
    except getopt.GetoptError:
        usage()
    else:
        if not args:
            usage()

    for (opt, optval) in options:
        if opt == '-s':
            Opts.service = optval
            if Opts.service == 'http': 
                Opts.port = 443
            elif Opts.service == 'smtp':
                Opts.port = 25
            elif Opts.service == 'xmpp-client':
                Opts.port = 5222
            elif Opts.service == 'xmpp-server':
                Opts.port = 5269
            else:
                print("Error: Unrecognized service name: {}".format(optval))
                usage()
        elif opt == '-u':
            Opts.ext_secure = {}

    Opts.hostname = args[0]
    if args[1:]:
        Opts.port = int(args[1])
    if args[2:]:
        Opts.transport = args[2]
    return


def do_query(ctx, qname, qtype):
    """Issue query for given qname, qtype and return results object"""
    try:
        results = ctx.general(name=qname, request_type=qtype,
                              extensions=Opts.ext_secure)
    except getdns.error as e:
        print(str(e))
        sys.exit(1)    

    return results


def certdata2hex(certdata):
    """Convert raw TLSA cert association data to hex string"""
    try:
        c = hexlify(certdata.tobytes()).decode()
    except AttributeError:
        c = hexlify(str(certdata))
    return c


def process_answers(results, qtype, qtype_filter=None, do_print=True):
    """Process answers, print, and return rdata array"""
    status = results.status
    rdata_list = []
    if status == getdns.RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            answers = reply['answer']
            for answer in answers:
                rdata = answer['rdata']
                rdata_p = ""
                if answer['type'] == getdns.RRTYPE_CNAME:
                    rdata_p = rdata['cname']
                elif answer['type'] == getdns.RRTYPE_TLSA:
                    rdata_p = "%d %d %d %s" % \
                              (rdata['certificate_usage'],
                               rdata['selector'], 
                               rdata['matching_type'],
                               certdata2hex(rdata['certificate_association_data']))
                elif answer['type'] == getdns.RRTYPE_SRV:
                    rdata_p = "%d %d %d %s" % \
                              (rdata['priority'],
                               rdata['weight'],
                               rdata['port'],
                               rdata['target'])
                elif answer['type'] == getdns.RRTYPE_MX:
                    rdata_p = "%d %s" % \
                              (rdata['preference'],
                               rdata['exchange'])
                if answer['type'] == qtype:
                    rdata_list.append(rdata_p)
                if do_print and (not qtype_filter or 
                                 (answer['type'] in qtype_filter)):
                    print("%s %d %s %s %s" %
                          (answer['name'], answer['ttl'], 
                           dns.rdataclass.to_text(answer['class']),
                           dns.rdatatype.to_text(answer['type']), 
                           rdata_p))

    elif status == getdns.RESPSTATUS_NO_SECURE_ANSWERS:
        print("%s: No DNSSEC secured responses found" % qname)

    else:
        print("%s: getdns.address() returned error: %d" % (qname, status))

    return rdata_list


if __name__ == '__main__':

    parse_args(sys.argv)

    ctx = getdns.Context()

    if not Opts.service or Opts.service == 'http':

        qname = "_%d._%s.%s" % (Opts.port, Opts.transport, Opts.hostname)
        results = do_query(ctx, qname, getdns.RRTYPE_TLSA)
        x = process_answers(results, getdns.RRTYPE_TLSA,
                            [getdns.RRTYPE_TLSA, getdns.RRTYPE_CNAME])

    elif Opts.service == 'smtp':

        results = do_query(ctx, Opts.hostname, getdns.RRTYPE_MX)
        x = process_answers(results, getdns.RRTYPE_MX,
                            [getdns.RRTYPE_MX, getdns.RRTYPE_CNAME])
        for entry in x:
            mx = entry.split()[1]
            qname = "_25._tcp.%s" % mx
            results = do_query(ctx, qname, getdns.RRTYPE_TLSA)
            y = process_answers(results, getdns.RRTYPE_TLSA,
                                [getdns.RRTYPE_TLSA, getdns.RRTYPE_CNAME])

    elif Opts.service == 'xmpp-client':

        qname = "_xmpp-client._tcp.%s" % (Opts.hostname)
        results = do_query(ctx, qname, getdns.RRTYPE_SRV)
        x = process_answers(results, getdns.RRTYPE_SRV,
                            [getdns.RRTYPE_SRV, getdns.RRTYPE_CNAME])
        for entry in x:
            prio, weight, port, target = entry.split()
            qname = "_%s._tcp.%s" % (port, target)
            results = do_query(ctx, qname, getdns.RRTYPE_TLSA)
            y = process_answers(results, getdns.RRTYPE_TLSA,
                                [getdns.RRTYPE_TLSA, getdns.RRTYPE_CNAME])

    elif Opts.service == 'xmpp-server':

        qname = "_xmpp-server._tcp.%s" % (Opts.hostname)
        results = do_query(ctx, qname, getdns.RRTYPE_SRV)
        x = process_answers(results, getdns.RRTYPE_SRV,
                            [getdns.RRTYPE_SRV, getdns.RRTYPE_CNAME])
        for entry in x:
            prio, weight, port, target = entry.split()
            qname = "_%s._tcp.%s" % (port, target)
            results = do_query(ctx, qname, getdns.RRTYPE_TLSA)
            y = process_answers(results, getdns.RRTYPE_TLSA,
                                [getdns.RRTYPE_TLSA, getdns.RRTYPE_CNAME])

