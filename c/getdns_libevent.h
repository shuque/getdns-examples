#include <getdns/getdns.h>
#include <getdns/getdns_ext_libevent.h>
#ifdef HAVE_EVENT2_EVENT_H
    #include <event2/event.h>
#else
    #include <event.h>
#endif

#ifndef HAVE_U_CHAR
    typedef unsigned char u_char;
#endif
