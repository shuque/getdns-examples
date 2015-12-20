#!/usr/bin/env python3
#
# 
# How do we set an use SNI?
# Disable SSL3 and below
#

import os.path, sys, socket, hashlib, pprint
import dns.resolver
import ssl

def usage():
    print("""\
Usage: {0} [hostname] [port]\
""".format(os.path.basename(sys.argv[0])))
    sys.exit(1)


def compute_hash(func, string):
    """compute hash of string using given hash function"""
    h = func()
    h.update(string)
    return h.hexdigest()


def get_certbundle():
    locations = [
        "/etc/ssl/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
    ]
    for f in locations:
        if os.path.exists(f):
            return f
    else:
        raise Exception("unable to find CA certificate bundle location")
        

if __name__ == '__main__':

    if (len(sys.argv) < 2) or (len(sys.argv) > 3):
        usage()
    else:
        hostname = sys.argv[1]
        try:
            port = int(sys.argv[2])
        except:
            port = 443

    certbundle = get_certbundle()
    ai_list = socket.getaddrinfo(hostname, port, 
                                 socket.AF_UNSPEC, socket.SOCK_STREAM)

    for (af, socktype, proto, cano, saddr) in ai_list:

        ipaddr, port = saddr[0:2]

        print("\nConnecting to %s at address %s ..." % (hostname, ipaddr))

        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(certbundle)

        conn = context.wrap_socket(socket.socket(af, socktype),
                                   server_hostname=hostname)
        #conn = context.wrap_socket(socket.socket(af, socktype))
        conn.connect((ipaddr, port))
        cert = conn.getpeercert()
        pprint.pprint(cert)

        print("Closing connection ..")
        conn.close()

