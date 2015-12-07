/*
 * TODO:
 * search lists?
 * canonicalize hostname
 * Error processing - don't return/exit or bailout
 *
 */

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

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

/* max possible length of a presentation-format IPv6 string */
#define MAX_IPSTRING 40

void usage(const char *progname)
{
    fprintf(stdout, "Usage: %s [-s46] <hostname1> <hostname2> ...\n"
	    "       -s: only return DNSSEC secured results\n"  
	    "       -4: only return IPv4 addresses\n"
	    "       -6: only return IPv6 addresses\n", progname);
    exit(1);
}


int main(int argc, char * const *argv)
{
    getdns_return_t rc = (getdns_return_t) 0;
    const char     *progname;
    int            opt;
    const char     *hostname;
    uint8_t        secure_only=0, v4_only=0, v6_only=0, exit_status=0;
    uint32_t       status;
    char           ipstring[MAX_IPSTRING];
    getdns_context *context;
    getdns_dict    *response;
    getdns_dict    *extensions = NULL;
    getdns_list    *addresses;
    size_t         cnt_addr;
    getdns_dict    *address;
    getdns_bindata *addr_type;
    getdns_bindata *addr_data;

    if ((progname = strrchr(argv[0], '/')))
	progname++;
    else
	progname = argv[0];

    while ((opt = getopt(argc, argv, "sh46")) != -1) {
	switch(opt) {
	case 's': secure_only = 1; break;
	case '4': v4_only = 1; break;
	case '6': v6_only = 1; break;
	default:  
	    usage(progname);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc <  1) {
	usage(progname);
    }

    while ( (hostname = *argv++) ) {

	if ((rc = getdns_context_create(&context, 1))) {
	    fprintf(stderr, "FAIL: Error creating getdns context: %s\n", getdns_get_errorstr_by_id(rc));
	    return 1;
	}

	if (secure_only) {
	    if (! (extensions = getdns_dict_create())) {
		fprintf(stderr, "FAIL: Error creating extensions dict\n");
		return 1;
	    }
	    if ((rc = getdns_dict_set_int(extensions, "dnssec_return_only_secure", 
					  GETDNS_EXTENSION_TRUE))) {
		fprintf(stderr, "FAIL: Error setting dnssec_return_only_secure: %s\n",
			getdns_get_errorstr_by_id(rc));
		return 1;
	    }
	}


	if ((rc = getdns_address_sync(context, hostname, extensions, &response))) {
	    fprintf(stderr, "FAIL: Error looking up addresses for %s: %s\n", hostname, 
		    getdns_get_errorstr_by_id(rc));
	    exit_status = 1;
	    continue;
	}

	if ((rc = getdns_dict_get_int(response, "status", &status))) {
	    fprintf(stderr, "FAIL: Error obtaining status code, %s\n", getdns_get_errorstr_by_id(rc));
	    exit_status = 1;
	    continue;
	}

	if (status == 903) {
	    fprintf(stderr, "FAIL: %s No secure responses obtained\n", hostname);
	    exit_status = 1;
	    continue;
	} else if (status == 901) {
	    fprintf(stderr, "FAIL: %s Non existent domain name\n", hostname);
	    exit_status = 1;
	    continue;
	}


	if ((rc = getdns_dict_get_list(response, "just_address_answers",
				       &addresses))) {
	    fprintf(stderr, "FAIL: Error getting addresses from response dict: %s\n",
		    getdns_get_errorstr_by_id(rc));
	    exit_status = 1;
	    continue;
	}

	if ((rc = getdns_list_get_length(addresses, &cnt_addr))) {
	    fprintf(stderr, "FAIL: Error getting address lengths list: %s\n",
		    getdns_get_errorstr_by_id(rc));
            exit_status = 1;
            continue;
	}

	if (cnt_addr <= 0) {
	    printf("FAIL: %s: No addresses found.\n", hostname);
            exit_status = 1;
            continue;
	}

	for (size_t i = 0; i < cnt_addr; i++) {
	    
	    if ((rc = getdns_list_get_dict(addresses, i, &address))) {
		fprintf(stderr, "FAIL: Error getting address list: %s\n", getdns_get_errorstr_by_id(rc));
		exit_status = 1;
		break;
	    }

	    if ((rc = getdns_dict_get_bindata(address, "address_type", 
					      &addr_type))) {
		fprintf(stderr, "FAIL: Error getting addr_type: %s\n", getdns_get_errorstr_by_id(rc));
		exit_status = 1;
		break;
	    }

	    if ((rc = getdns_dict_get_bindata(address, "address_data", 
					      &addr_data))) {
		fprintf(stderr, "FAIL: Error getting addr_data: %s\n", getdns_get_errorstr_by_id(rc));
		exit_status = 1;
		break;
	    }

	    if (!strncmp((const char *) addr_type->data, "IPv4", 4)) {
		if (v4_only || (!v4_only && !v6_only))
		    fprintf(stdout, "OK: %s IPv4 %s\n", hostname, 
			    inet_ntop(AF_INET, addr_data->data, ipstring, 
				      sizeof(ipstring)));
	    } else if (!strncmp((const char *) addr_type->data, "IPv6", 4)) {
		if (v6_only || (!v4_only && !v6_only))
		    fprintf(stdout, "OK: %s IPv6 %s\n", hostname,
			    inet_ntop(AF_INET6, addr_data->data, ipstring, 
				      sizeof(ipstring)));
	    } else  {
		/* shouldn't get here */
		fprintf(stderr, "FAIL: Unknown address type\n");
		rc = 1;
		break;
	    }

	}

    }

    return exit_status;
}

