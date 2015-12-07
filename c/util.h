/*
 * util.h
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns/getdns.h>

char *bindata2string(getdns_bindata *b);
void bindata_printhex(getdns_bindata *b);
