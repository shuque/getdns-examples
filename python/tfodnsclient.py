#!/usr/bin/env python3
#
# Small DNS TCP stub client that uses TCP Fast Open (TFO) if available.
# A DNS server known to suport TFO is Google Public DNS.
# (Note: doesn't use getdns. getdns will automatically use TFO if
# compiled with TFO support).
#

import os, os.path, sys
import struct, socket
import dns.message, dns.rdatatype
from binascii import hexlify

try:
    socket.MSG_FASTOPEN
except:
    print("No support for TCP Fast Open")
    sys.exit(1)

RBUFSIZE = 2048
progname = os.path.basename(sys.argv[0])

try:
    ip4addr, port, qname, qtype = sys.argv[1:]
    port = int(port)
except:
    print("Usage: %s <addr> <port> <qname> <qtype>" % progname)
    sys.exit(1)


msg = dns.message.make_query(qname, qtype, rdclass=1).to_wire()
msg = struct.pack('!H', len(msg)) + msg

s = socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

octetsSent = 0
while (octetsSent < len(msg)):
    sentn = s.sendto(msg[octetsSent:], socket.MSG_FASTOPEN, (ip4addr, port))
    if sentn == 0:
        raise(ValueError, "sendto() returned 0 bytes")
    octetsSent += sentn

response = b""
while True:
    (data, saddr) = s.recvfrom(RBUFSIZE)
    response += data
    rlen = len(data)
    print("DEBUG: Read %d octets" % rlen)
    if rlen == 0:
        break

s.close()
print("\Response=%s\n" % hexlify(response))

resp_len, = struct.unpack('!H', response[0:2])
resp_msg = response[2:2+resp_len]
m = dns.message.from_wire(resp_msg)
print(m)
