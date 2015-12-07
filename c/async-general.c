/*
 * aget-general.c ("a" means asynchronous version)
 *
 * Usage: ./aget-general <qname> <qtype>
 *
 *         qname is a domain name
 *         qtype is an integer corresponding to the query type
 * 
 * Prints out rrname, rrtype, and rdata in hex for each RR in the
 * answer section of the DNS responses.
 * 
 * Shumon Huque <shuque@gmail.com>
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns_libevent.h>
#include "util.h"

#define UNUSED_PARAM(x) ((void)(x))


void callback(getdns_context *ctx,
	     getdns_callback_type_t cbtype,
	     getdns_dict *response,
	     void *uarg,
	     getdns_transaction_t tid)
{
    getdns_return_t rc;

    if (cbtype == GETDNS_CALLBACK_COMPLETE) {

	uint32_t status;
	rc = getdns_dict_get_int(response, "status", &status);
	if (status != GETDNS_RESPSTATUS_GOOD) {
	    (void) fprintf(stderr, "Bad response status: %d", status);
	    return;
	}

	getdns_list *replies_tree;
	rc = getdns_dict_get_list(response, "replies_tree", &replies_tree);
	if (rc != GETDNS_RETURN_GOOD) {
	    (void) fprintf(stdout, "dict_get_list: replies_tree: rc=%d\n", rc);
	    return;
	}

	size_t reply_count;
	rc = getdns_list_get_length(replies_tree, &reply_count);

	for ( size_t i = 0; i < reply_count; i++ ) {

	    getdns_dict *reply;
	    rc = getdns_list_get_dict(replies_tree, i, &reply);
	    getdns_list *answer;
	    rc = getdns_dict_get_list(reply, "answer", &answer);
	    size_t rr_count;
	    rc = getdns_list_get_length(answer, &rr_count);

	    for ( size_t j = 0; j < rr_count; j++ ) {

		(void) putc('\n', stdout);
		getdns_dict *rr = NULL;
		rc = getdns_list_get_dict(answer, j, &rr);

		getdns_bindata *rrname;
		rc = getdns_dict_get_bindata(rr, "name", &rrname);
		char *fqdn;
		rc = getdns_convert_dns_name_to_fqdn(rrname, &fqdn);
		(void) fprintf(stdout, "rrname=%s\n", fqdn);
		free(fqdn);

		uint32_t rrtype;
		rc = getdns_dict_get_int(rr, "type", &rrtype);
		(void) fprintf(stdout, "rrtype=%d\n", rrtype);

		getdns_dict *rdata = NULL;
		rc = getdns_dict_get_dict(rr, "rdata", &rdata);
		getdns_bindata *rdata_raw;
		rc = getdns_dict_get_bindata(rdata, "rdata_raw", &rdata_raw);
		bindata_printhex(rdata_raw);
	    }

	}

    } else if (cbtype == GETDNS_CALLBACK_CANCEL)
        fprintf(stderr, "Callback was cancelled, uarg=%s, tid=%d\n", 
		(char *) uarg, (int) tid);
    else
        fprintf(stderr, "Callback failed with rc=%d, uarg=%s, tid=%d\n", 
		cbtype, (char *) uarg, (int) tid);

    getdns_dict_destroy(response);
    UNUSED_PARAM(ctx);
    return;
}


int main(int argc, char **argv)
{
    const char *progname;
    getdns_context *ctx = NULL;
    getdns_return_t rc;

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

    /* Create an event base and put it in the context */
    struct event_base *evb;
    evb = event_base_new();
    if (evb == NULL) {
	(void) fprintf(stderr, "event_base_new() failed\n");
	getdns_context_destroy(ctx);
	return 1;
    }

    (void) getdns_extension_set_libevent_base(ctx, evb);
    getdns_transaction_t tid = 0;
    char* uarg = "somestring";

    rc = getdns_general(ctx, qname, qtype, NULL, uarg, &tid, callback);
    (void) fprintf(stdout, "main:getdns_general() rc=%d\n", rc);

    if (rc == GETDNS_RETURN_BAD_DOMAIN_NAME) {
	(void) fprintf(stderr, "getdns_general() bad domain name\n");
	event_base_free(evb);
	getdns_context_destroy(ctx);
	return 1;
    } else {
	(void) fprintf(stdout, "calling event loop ...\n");
	(void) event_base_dispatch(evb);
    }

    event_base_free(evb);
    getdns_context_destroy(ctx);
    return 0;
}

