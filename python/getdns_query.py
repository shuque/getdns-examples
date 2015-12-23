#!/usr/bin/env python
#
# getdns_query.py (Work in progress) - Shumon Huque
#
# A tool to test getdns library features.
# Modelled after the getdns_query.c test program included in the
# getdns library source distribution.
#
# TODO
# - async mode
# 

import sys, getopt, os.path, socket, pprint
import getdns


def usage():
    print("""\
Usage: {0} [@<server>] [+extension] [<qname>] [<qtype>]

Options:

    -a Perform asynchronous resolution (default = synchronous)
    -A address lookup (<type> is ignored)
    -B Batch mode. Schedule all messages before processing responses.
    -b <bufsize>Set edns0 max_udp_payload size
    -c Send Client Subnet privacy request
    -D Set edns0 do bit
    -d clear edns0 do bit
    -e <idle_timeout> Set idle timeout in miliseconds
    -F <filename> read the queries from the specified file
    -G general lookup
    -H hostname lookup. (<name> must be an IP address; <type> is ignored)
    -h Print this help
    -i Print api information
    -I Interactive mode (> 1 queries on same context)
    -j Output json response dict
    -J Pretty print json response dict
    -k Print root trust anchors
    -n Set TLS authentication mode to NONE (default)
    -m Set TLS authentication mode to HOSTNAME
    -p Pretty print response dict
    -P <blocksize> Pad TLS queries to a multiple of blocksize
    -r Set recursing resolution type
    -q Quiet mode - don't print response
    -s Set stub resolution type (default = recursing)
    -S service lookup (<type> is ignored)
    -t <timeout>Set timeout in miliseconds
    -T Set transport to TCP only
    -O Set transport to TCP only keep connections open
    -L Set transport to TLS only keep connections open
    -E Set transport to TLS with TCP fallback only keep connections open
    -R Set transport to STARTTLS with TCP fallback only keep connections open
    -u Set transport to UDP with TCP fallback
    -U Set transport to UDP only

    Available extensions are:
      +dnssec_return_status
      +dnssec_return_only_secure
      +dnssec_return_validation_chain
      +return_both_v4_and_v6
      +add_opt_parameters
      +add_warning_for_bad_dns
      +specify_class
      +return_call_debugging

""".format(os.path.basename(sys.argv[0])))    
    sys.exit(1)


class Options:
    """Options data structure"""
    server          = None
    async           = False
    batch           = False
    lookup_address  = False
    lookup_hostname = False
    lookup_srv      = False
    lookup_general  = True
    filename        = None
    api_info        = False
    interactive     = False
    root_ta         = False
    keep_open       = False


Exts = dict()

def parse_args(arglist):
    """Parse command line arguments."""
    while arglist:

        arg = arglist.pop(0)

        if arg == '-h':
            usage()

        elif arg.startswith('@'):
            Options.server = arg[1:]
            ctx.upstream_recursive_servers = [get_address_dict(arg[1:])]
            
        elif arg == '+dnssec_return_status':
            Exts['dnssec_return_status'] = getdns.EXTENSION_TRUE

        elif arg == '+dnssec_return_only_secure':
            Exts['dnssec_return_only_secure'] = getdns.EXTENSION_TRUE

        elif arg == '+dnssec_return_validation_chain':
            Exts['dnssec_return_validation_chain'] = getdns.EXTENSION_TRUE

        elif arg == '+return_both_v4_and_v6':
            Exts['return_both_v4_and_v6'] = getdns.EXTENSION_TRUE

        elif arg == '+return_call_debugging':
            Exts['return_call_debugging'] = getdns.EXTENSION_TRUE

        elif arg == '-a':
            Options.async = True

        elif arg == '-A':
            Options.lookup_address = True

        elif arg == '-B':
            Options.batch = True

        elif arg == '-b':
            ctx.edns_maximum_udp_payload_size = int(arglist.pop(0))

        elif arg == '-c':
            ctx.edns_client_subnet_private = 1

        elif arg == '-D':
            ctx.edns_do_bit = 1

        elif arg == '-d':
            ctx.edns_do_bit = 0

        elif arg == '-e':
            ctx.idle_timeout = int(arglist.pop(0))

        elif arg == '-F':
            Options.filename = arglist.pop(0)

        elif arg == '-G':
            Options.lookup_general = True

        elif arg == '-H':
            Options.lookup_hostname = True

        elif arg == '-i':
            Options.api_info = True

        elif arg == '-I':
            Options.interactive = True

        elif arg == '-k':
            Options.root_ta = True

        elif arg == '-n':
            ctx.tls_authentication = getdns.AUTHENTICATION_NONE

        elif arg == '-m':
            ctx.tls_authentication = getdns.AUTHENTICATION_HOSTNAME

        elif arg == '-P':
            ctx.tls_query_padding_blocksize = int(arglist.pop(0))

        elif arg == '-r':
            ctx.resolution_type = getdns.RESOLUTION_RECURSING

        elif arg == '-s':
            ctx.resolution_type = getdns.RESOLUTION_STUB

        elif arg == '-S':
            Options.lookup_srv = True

        elif arg == '-t':
            ctx.timeout = int(arglist.pop(0))

        elif arg == '-T':
            ctx.dns_transport_list = [ getdns.TRANSPORT_TCP ]

        elif arg == '-O':
            ctx.dns_transport_list = [ getdns.TRANSPORT_TCP ]
            Options.keep_open = True

        elif arg == '-L':
            ctx.dns_transport_list = [ getdns.TRANSPORT_TLS ]
            Options.keep_open = True

        elif arg == '-E':
            ctx.dns_transport_list = [ getdns.TRANSPORT_TLS, getdns.TRANSPORT_TCP ]
            Options.keep_open = True

        elif arg == '-u':
            ctx.dns_transport_list = [ getdns.TRANSPORT_UDP, getdns.TRANSPORT_TCP ]

        elif arg == '-U':
            ctx.dns_transport_list = [ getdns.TRANSPORT_UDP ]

        elif arg.startswith('-'):
            print("ERROR: Invalid option: {}\n".format(arg))
            usage()

        else:
            arglist.insert(0, arg)
            break

    if arglist:
        qname = arglist.pop(0)
    else:
        usage()

    if arglist:
        qtype = arglist.pop(0).upper()
    else:
        qtype = 'A'

    return (qname, qtype)


def rrtypecode(qtype):
    try:
        rrtype = int(qtype)
        return rrtype
    except ValueError:
        try:
            rrtype = eval("getdns.RRTYPE_%s" % qtype.upper())
        except AttributeError:
            print "Unknown DNS record type: %s" % qtype
            sys.exit(1)
        else:
            return rrtype


def get_address_dict(address):
    """Turn IP address string into a getdns address dictionary"""
    af = None
    try:
        if address.find('.') != -1:
            socket.inet_pton(socket.AF_INET, address)
            af = 'IPv4'
        elif address.find(':') != -1:
            socket.inet_pton(socket.AF_INET6, address)
            af = 'IPv6'
    except socket.error:
        pass
    if not af:
        raise ValueError("%s isn't an IPv4 or IPv6 address" % address)
    else:
        return {'address_data': address, 'address_type': af}


if __name__ == '__main__':

    ctx = getdns.Context()
    qname, qtype = parse_args(sys.argv[1:])
    qtype = rrtypecode(qtype)

    if Options.api_info:
        pprint.pprint(ctx.get_api_information())
        sys.exit(0)

    try:

        if Options.lookup_address:
            res = ctx.address(qname, extensions=Exts)
        elif Options.lookup_hostname:
            res = ctx.hostname(get_address_dict(qname), extensions=Exts)
        elif Options.lookup_srv:
            res = ctx.service(qname, extensions=Exts)
        elif Options.lookup_general:
            res = ctx.general(qname, request_type=qtype, extensions=Exts)

    except getdns.error as e:

        print(str(e))
        sys.exit(1)

    status = res.status
    if status == getdns.RESPSTATUS_GOOD:
        for reply in res.replies_tree:
            answers = reply['answer']           # list of 1 here
            for answer in answers:
                pprint.pprint(answer)
    elif status == getdns.RESPSTATUS_NO_NAME:
        print("Error: %s, %s: no such name" % (qname, qtype))
    elif status == getdns.RESPSTATUS_NO_SECURE_ANSWERS:
        print("Error: %s, %s: no secure answers" % (qname, qtype))
    elif status == getdns.RESPSTATUS_ALL_TIMEOUT:
        print("Error: %s, %s: query timed out" % (qname, qtype))
    else:
        print("Error: %s, %s: error return code: %d" % (qname, qtype, status))
