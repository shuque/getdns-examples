#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <getdns/getdns_ext_libevent.h>
#ifdef HAVE_EVENT2_EVENT_H
    #include <event2/event.h>
#else
    #include <event.h>
#endif

/* shouldn't we get this declaration from string.h? */
char *strdup();

typedef struct name_info {
    const char *name;
    uint8_t secure_only, v4_only, v6_only;
} name_info;


/* max possible length of a presentation-format IPv6 string */
#define MAX_IPSTRING 40

void usage(const char *progname)
{
    fprintf(stdout, "Usage: %s [-s46] <hostname1> <hostname2> ...\n"
            "       -s: only return DNSSEC secured results\n"
            "       -4: only return IPv4 addresses\n"
	    "       -6: only return IPv6 addresses\n"
	    "\n"
	    "With no hostnames on command line, reads stdin for them.\n",
	    progname);
    exit(1);
}


#define UNUSED_PARAM(x) ((void) (x))

/* 
 * Set up the callback function for procesing results
 */

void callback(getdns_context *ctx,
	      getdns_callback_type_t cb_type,
	      getdns_dict *response, 
	      void *userarg,
	      getdns_transaction_t tid)
{
    UNUSED_PARAM(ctx);
    getdns_return_t rc;
    uint32_t status;
    name_info *nip = (name_info *) userarg;
    const char *hostname = nip->name;
    uint8_t v4_only = nip->v4_only, v6_only = nip->v6_only;
    getdns_list    *addresses;
    size_t         cnt_addr;
    getdns_dict    *address;
    getdns_bindata *addr_type;
    getdns_bindata *addr_data;
    char           ipstring[MAX_IPSTRING];

    if (cb_type == GETDNS_CALLBACK_COMPLETE) {

        if ((rc = getdns_dict_get_int(response, "status", &status))) {
            fprintf(stderr, "FAIL: %s: Error obtaining status code: %s\n", hostname, getdns_get_errorstr_by_id(rc));
	    goto cleanup;
        }

        if (status == 903) {
            fprintf(stderr, "FAIL: %s No secure responses obtained\n", hostname);
	    goto cleanup;
        } else if (status == 901) {
            fprintf(stderr, "FAIL: %s Non existent domain name\n", hostname);
	    goto cleanup;
        }

        if ((rc = getdns_dict_get_list(response, "just_address_answers", &addresses))) {
            fprintf(stderr, "FAIL: Error getting addresses from response dict: %s\n", getdns_get_errorstr_by_id(rc));
	    goto cleanup;
        }

        if ((rc = getdns_list_get_length(addresses, &cnt_addr))) {
            fprintf(stderr, "FAIL: Error getting address lengths list: %s\n", getdns_get_errorstr_by_id(rc));
	    goto cleanup;
        }

        if (cnt_addr <= 0) {
            printf("FAIL: %s: No addresses found.\n", hostname);
	    goto cleanup;
        }

        for (size_t i = 0; i < cnt_addr; i++) {

            if ((rc = getdns_list_get_dict(addresses, i, &address))) {
                fprintf(stderr, "FAIL: %s: Error getting address list: %s\n", hostname, getdns_get_errorstr_by_id(rc));
		break;
            }

            if ((rc = getdns_dict_get_bindata(address, "address_type", &addr_type))) {
                fprintf(stderr, "FAIL: %s: Error getting addr_type: %s\n", hostname, getdns_get_errorstr_by_id(rc));
		break;
            }

            if ((rc = getdns_dict_get_bindata(address, "address_data", &addr_data))) {
                fprintf(stderr, "FAIL: %s: Error getting addr_data: %s\n", hostname, getdns_get_errorstr_by_id(rc));
                break;
            }

            if (!strncmp((const char *) addr_type->data, "IPv4", 4)) {
                if (v4_only || (!v4_only && !v6_only))
                    fprintf(stdout, "OK: %s IPv4 %s\n", hostname,
                            inet_ntop(AF_INET, addr_data->data, ipstring, sizeof(ipstring)));
            } else if (!strncmp((const char *) addr_type->data, "IPv6", 4)) {
                if (v6_only || (!v4_only && !v6_only))
                    fprintf(stdout, "OK: %s IPv6 %s\n", hostname,
                            inet_ntop(AF_INET6, addr_data->data, ipstring, sizeof(ipstring)));
            } else  {
                /* shouldn't get here */
                fprintf(stderr, "FAIL: Unknown address type\n");
                break;
            }

        }

    } else if (cb_type == GETDNS_CALLBACK_CANCEL) {

        fprintf(stderr, "Callback with ID %"PRIu64" was cancelled.", tid);

    } else {

        fprintf(stderr, "Got callback_type of %d. Exiting.\n", cb_type);

    }

cleanup:
    free(nip);
    getdns_dict_destroy(response);
    return;
}


int main(int argc, char **argv)
{

    const char        *progname;
    int               opt;
    getdns_context    *context = NULL;
    getdns_dict       *extensions = NULL;
    getdns_return_t   rc;
    char              *hostname;
    uint8_t           secure_only=0, v4_only=0, v6_only=0, exit_status=1;
    struct event_base *evb;

    if ((progname = strrchr(argv[0], '/')))
        progname++;
    else
        progname = argv[0];

    while ((opt = getopt(argc, argv, "sh46")) != -1) {
        switch(opt) {
        case 's': secure_only = 1; break;
        case '4': v4_only = 1; break;
        case '6': v6_only = 1; break;
	case 'h': usage(progname);
        default:  usage(progname);
        }
    }
    argc -= optind;
    argv += optind;

    rc = getdns_context_create(&context, 1);
    if (rc != GETDNS_RETURN_GOOD) {
	fprintf(stderr, "FAIL: Error creating getdns context: %s\n", getdns_get_errorstr_by_id(rc));
	return GETDNS_RETURN_GENERIC_ERROR;
    }

    if (secure_only) {
	if (! (extensions = getdns_dict_create())) {
	    fprintf(stderr, "FAIL: Error creating extensions dict\n");
	    return 1;
	}
	if ((rc = getdns_dict_set_int(extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE))) {
	    fprintf(stderr, "FAIL: Error setting dnssec_return_only_secure: %s\n", getdns_get_errorstr_by_id(rc));
	    return 1;
	}
    }

    if ( (evb = event_base_new()) == NULL ) {
	fprintf(stderr, "FAIL: event base creation failed.\n");
	getdns_context_destroy(context);
	return GETDNS_RETURN_GENERIC_ERROR;
    }

    (void) getdns_extension_set_libevent_base(context, evb);

    if (argc <  1) {

	/* batch mode here - read and process lines of hostnames from standard input */
	char linebuf[1024];
	while ( scanf("%s", linebuf) != EOF ) {
	    hostname = strdup(linebuf);
	    name_info *nip = (name_info *) malloc(sizeof(name_info));
	    nip->name = hostname;
	    nip->secure_only = secure_only;
	    nip->v4_only = v4_only;
	    nip->v6_only = v6_only;

	    getdns_transaction_t tid = 0;

	    rc = getdns_address(context, hostname, extensions, (void *) nip, &tid, callback);
	    if (rc != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "ERROR: %s getdns_address failed: %s\n", hostname, getdns_get_errorstr_by_id(rc));
		event_base_free(evb);
		getdns_context_destroy(context);
		return GETDNS_RETURN_GENERIC_ERROR;
	    }

	}

    } else {

	while ( (hostname = *argv++) ) {

	    name_info *nip = (name_info *) malloc(sizeof(name_info));
	    nip->name = hostname;
	    nip->secure_only = secure_only;
	    nip->v4_only = v4_only;
	    nip->v6_only = v6_only;

	    getdns_transaction_t tid = 0;

	    rc = getdns_address(context, hostname, extensions, (void *) nip, &tid, callback);
	    if (rc != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "ERROR: %s getdns_address failed: %s\n", hostname, getdns_get_errorstr_by_id(rc));
		event_base_free(evb);
		getdns_context_destroy(context);
		return GETDNS_RETURN_GENERIC_ERROR;
	    }

	}  /* while loop */

    }

    int e_rc = event_base_dispatch(evb);

    if (e_rc == -1)
	fprintf(stderr, "Error in dispatching events.\n");
    else
	exit_status = 0;

    event_base_free(evb);
    getdns_context_destroy(context);

    return exit_status;
}
