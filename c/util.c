/*
 * util.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns/getdns.h>

char *bindata2string(getdns_bindata *b)
{
    char *out;
    out = (char *) malloc(b->size + 1);
    snprintf(out, b->size+1, "%s", b->data);
    return out;
}

void bindata_printhex(getdns_bindata *b) {
    size_t k;
    for ( k = 0; k < b->size; k++ ) {
        fprintf(stdout, "%02x", (unsigned int) *(b->data+k));
    }
    (void) putc('\n', stdout);
    return;
}
