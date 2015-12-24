#!/usr/bin/env python
#
# getdns_query.py (Work in progress) - Shumon Huque
#
# A tool to test getdns library features.
# Modelled after the getdns_query.c test program included in the
# getdns library source distribution.
#
# TODO
# - non-pretty print option: display presentation format response RRs
# - Support setting EDNS options
# - -k: Display root trust anchors in more detail
# - -q: quiet mode
# - Support setting of qclass
# - Use: getdns.get_errorstr_by_id()?
# - Support getdns_context_set_dnssec_trust_anchors()


import sys, getopt, os.path, socket, pprint
import getdns


def usage():
    print("""\
Usage: {0} [@<server>] [+extension] [<qname>] [<qtype>]

Options:

    -h Print this help message

    @server Set upstream recursive server to query.
            "server" is an IP address, optionally followed by
            a port (@), TLS port (#), and TLS hostname (~), e.g.
            @127.0.0.1
            @10.8.9.17#853~rdns.example.com

    -a Perform asynchronous resolution (default = synchronous)
    -r Set recursing resolution type
    -s Set stub resolution type (default = recursing)
    -q Quiet mode - don't print response

    -A address lookup (<type> is ignored)
    -H hostname lookup. (<name> must be an IP address; <type> is ignored)
    -S service lookup (<type> is ignored)
    -G general lookup (default)
    -i Print api information (ignores qname, qtype)
    -k Print root trust anchors (ignores qname, qtype)

    -B Batch mode. Schedule all messages before processing responses.
    -F <filename> read the queries from the specified file
    -I Interactive mode (> 1 queries on same context)
    -b <bufsize> Set edns0 max_udp_payload size
    -c Send Client Subnet privacy request
    -D Set edns0 do bit
    -d clear edns0 do bit
    -e <idle_timeout> Set idle timeout in miliseconds
    -P <blocksize> Pad TLS queries to a multiple of blocksize
    -t <timeout>Set timeout in miliseconds

    -n Set TLS authentication mode to NONE (default)
    -m Set TLS authentication mode to HOSTNAME
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
    quiet           = False
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
            set_recursive_server(ctx, Options.server)
            
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
            # Batch mode is currently a no-op. Async mode automatically batches
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

        elif arg == '-q':
            Options.quiet = True

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

        elif arg.startswith('+'):
            print("ERROR: Invalid extension: {}\n".format(arg[1:]))
            usage()

        else:
            arglist.insert(0, arg)
            break

    if Options.api_info or Options.root_ta or Options.filename:
        # ignore unneeded qname and qtype if specified
        return (None, None)

    if arglist:
        qname = arglist.pop(0)
    else:
        usage()

    if arglist:
        qtype = arglist.pop(0).upper()
    else:
        qtype = 'A'

    return (qname, qtype)


def set_recursive_server(ctx, server):
    """set upstream recursive server in the getdns context.
    server is an IP address, optionally followed by a prefixed
    port (@), TLS port (#), and TLS hostname (~).
    """
    l_server = list(server)
    position = dict()
    prefix = dict(address=None, port='@', tls_port='#', tls_auth_name='~')
    for key, value in prefix.items():
        if prefix[key] == None:
            position[key] = 0
        else:
            n = server.find(value)
            if n != -1:
                l_server[n] = '\x00'
                position[key] = n+1
    values = ''.join(l_server).split('\x00')
    components = sorted(position, key=lambda k: position[k])
    zipped = (list(zip(components, values)))
    d = get_address_dict(zipped[0][1])
    for x, y in zipped[1:]:
        if x == 'port' or x == 'tls_port':
            d[x] = int(y)
        else:
            d[x] = y
    ctx.upstream_recursive_servers = [d]
    return


def rrtypecode(qtype):
    """return numeric code for given RR type"""
    try:
        rrtype = int(qtype)
    except ValueError:
        try:
            rrtype = eval("getdns.RRTYPE_%s" % qtype.upper())
        except AttributeError:
            print("Unknown DNS record type: {}".format(qtype))
            sys.exit(1)
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


def callback(cbtype, res, userarg, tid):
    """Callback function for asynchronous mode queries"""
    if cbtype == getdns.CALLBACK_COMPLETE:
        status = res.status
        if status == getdns.RESPSTATUS_GOOD:
            if Options.quiet:
                print_status(res, userarg)
            else:
                for reply in res.replies_tree:
                    pprint.pprint(reply)
        elif status == getdns.RESPSTATUS_NO_SECURE_ANSWERS:
            print("{}: No DNSSEC secured responses found".format(userarg))
        else:
            print("{}: getdns returned error: {}".format(userarg, status))
    elif cbtype == getdns.CALLBACK_CANCEL:
        print('Callback cancelled')
    elif cbtype == getdns.CALLBACK_TIMEOUT:
        print('Callback: Query timed out')
    else:
        print("Callback: Unknown error: {}".format(cbtype))


def do_query_async(ctx, qname, qtype):
    """Perform queries asynchronously"""
    qtype = rrtypecode(qtype)
    tid = None
    userarg = "{} {}".format(qname, qtype)
    try:
        if Options.lookup_address:
            userarg = "address: {}".format(qname)
            tid = ctx.address(qname, extensions=Exts, callback=callback,
                              userarg=userarg)
        elif Options.lookup_hostname:
            userarg = "hostname: {}".format(qname)
            tid = ctx.hostname(get_address_dict(qname), extensions=Exts,
                               callback=callback, userarg=userarg)
        elif Options.lookup_srv:
            userarg = "srv: {}".format(qname)
            tid = ctx.service(qname, extensions=Exts, callback=callback,
                              userarg=userarg)
        elif Options.lookup_general:
            userarg = "general: {} {}".format(qname, qtype)
            tid = ctx.general(qname, request_type=qtype, extensions=Exts,
                              callback=callback, userarg=userarg)
    except getdns.error as e:
        print("ERROR: query submission failed: {}: {}".format(userarg,str(e)))
    return tid


def do_query(ctx, qname, qtype):
    """Perform queries (synchronously)"""
    qtype = rrtypecode(qtype)
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
        if Options.quiet:
            print_status(res, "{} {}".format(qname, qtype))
        else:
            for reply in res.replies_tree:
                pprint.pprint(reply)
    elif status == getdns.RESPSTATUS_NO_NAME:
        print("Error: %s, %s: no such name" % (qname, qtype))
    elif status == getdns.RESPSTATUS_NO_SECURE_ANSWERS:
        print("Error: %s, %s: no secure answers" % (qname, qtype))
    elif status == getdns.RESPSTATUS_ALL_TIMEOUT:
        print("Error: %s, %s: query timed out" % (qname, qtype))
    else:
        print("Error: %s, %s: error return code: %d" % (qname, qtype, status))
    return


def print_status(res, query_info):
    """Print status of response"""
    print("{}: response status={}".format(query_info, res.status))
    return


if __name__ == '__main__':

    ctx = getdns.Context()
    qname, qtype = parse_args(sys.argv[1:])

    if Options.api_info:
        pprint.pprint(ctx.get_api_information())
        sys.exit(0)

    if Options.root_ta:
        pprint.pprint(getdns.root_trust_anchor())
        sys.exit(0)

    if Options.async:
        if Options.filename:
            tids = []
            for line in open(Options.filename):
                qname, qtype = line.split()
                tids.append(do_query_async(ctx, qname, qtype))
            ctx.run()
        else:
            tid = do_query_async(ctx, qname, qtype)
            ctx.run()
    else:
        if Options.filename:
            for line in open(Options.filename):
                qname, qtype = line.split()
                do_query(ctx, qname, qtype)
        else:
            do_query(ctx, qname, qtype)
