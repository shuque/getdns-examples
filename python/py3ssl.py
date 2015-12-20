#!/usr/bin/env python3
#
# 

import os.path, sys, socket, hashlib, pprint
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
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(certbundle)

        conn = context.wrap_socket(socket.socket(af, socktype),
                                   server_hostname=hostname)
        conn.connect((ipaddr, port))
        try:
            # Needs a very recent Python version
            print("Negotiated TLS version: %s" % conn.version())
        except AttributeError:
            pass
        cert = conn.getpeercert()
        pprint.pprint(cert)

        print("Closing connection ..")
        conn.close()
