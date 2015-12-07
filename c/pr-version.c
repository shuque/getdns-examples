/*
 * pr-version.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "util.h"

/* #include <getdns_libevent.h> */
#include <getdns/getdns.h>
#include <getdns/getdns_ext_libevent.h>
#ifdef HAVE_EVENT2_EVENT_H
    #include <event2/event.h>
#else
    #include <event.h>
#endif

int main(void)
{
    uint8_t exit_status = 0;
    getdns_context *ctx = NULL;
    getdns_return_t rc;
    getdns_dict *response;
    getdns_bindata *version, *implementation;
    char *out;

    rc = getdns_context_create(&ctx, 1);
    if (rc != GETDNS_RETURN_GOOD) {
	(void) fprintf(stderr, "Context creation failed: %d", rc);
	return 1;
    }

    response = getdns_context_get_api_information(ctx);

    if ((rc = getdns_dict_get_bindata(response, "version_string",
				      &version))) {
	fprintf(stderr, "FAIL: Error getting version: %s\n", getdns_get_errorstr_by_id(rc));
	exit_status = 1;
    } else {
	out = bindata2string(version);
	fprintf(stdout, "getdns version: %s\n", out);
	free(out);
    }

    if ((rc = getdns_dict_get_bindata(response, "implementation_string",
				      &implementation))) {
	fprintf(stderr, "FAIL: Error getting implementation: %s\n", getdns_get_errorstr_by_id(rc));
	exit_status = 1;
    } else {
	out = bindata2string(implementation);
	fprintf(stdout, "getdns implementation: %s\n", out);
	free(out);
    }

    getdns_context_destroy(ctx);
    return exit_status;
}
