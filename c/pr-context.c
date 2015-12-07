/*
 * pr-context.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

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
    getdns_context *ctx = NULL;
    getdns_return_t rc;
    getdns_dict *response;

    rc = getdns_context_create(&ctx, 1);
    if (rc != GETDNS_RETURN_GOOD) {
	(void) fprintf(stderr, "Context creation failed: %d", rc);
	return 1;
    }

    response = getdns_context_get_api_information(ctx);
    (void) fprintf(stderr, "%s\n", getdns_pretty_print_dict(response));

    getdns_context_destroy(ctx);
    return 0;
}
