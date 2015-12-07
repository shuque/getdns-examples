/*
 * responsedict.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns_libevent.h>
#include "util.h"


int main(int argc, char **argv)
{
    getdns_context *ctx = NULL;
    getdns_return_t rc;
    getdns_dict *response;
    const char *progname;

    if ((progname = strrchr(argv[0], '/')))
        progname++;
    else
        progname = argv[0];

    if (argc != 3) {
	(void) fprintf(stderr, "\nUsage %s <qname> <qtype>\n\n"
		       "\tqname: a domain name\n"
		       "\tqtype: an integer corresponding to the query type\n\n",
		       progname);
	return 1;
    }

    const char *qname = argv[1];
    const uint16_t qtype = atoi(argv[2]);

    rc = getdns_context_create(&ctx, 1);
    if (rc != GETDNS_RETURN_GOOD) {
	(void) fprintf(stderr, "Context creation failed: %d", rc);
	return 1;
    }

    rc = getdns_general_sync(ctx, qname, qtype, NULL, &response);
    if (rc != GETDNS_RETURN_GOOD) {
	(void) fprintf(stderr, "getdns_general() failed with rc=%d\n", rc);
	getdns_context_destroy(ctx);
	return 1;
    }

    uint32_t status;
    rc = getdns_dict_get_int(response, "status", &status);
    if (status != GETDNS_RESPSTATUS_GOOD) {
	(void) fprintf(stderr, "Bad response status: %d", status);
	return 1;
    }

    (void) fprintf(stderr, "%s\n", getdns_pretty_print_dict(response));

    getdns_context_destroy(ctx);
    return 0;
}
