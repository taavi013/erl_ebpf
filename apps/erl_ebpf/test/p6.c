#include <stdint.h>
#include <stddef.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <dns_util.h>

/* function prototypes */
extern int is_blacklisted_domain(void *name);
extern int is_whitelisted_domain(void *name);

#define NOT_IP          -1
#define NOT_UDP         -2
#define NOT_UDP_53      -3
#define NOT_DNS_REQ     -4

#define R_OK            0

#define R_PASS          R_OK
#define R_DROP          1

uint64_t program(void *buff)
{
    int header_len;
    struct ip *ip_header = buff;
    struct udphdr *udp_header;
    dns_header_t *dns;
    dns_question_t *question;

    if( ip_header->ip_v == 4 ){
      if( ip_header->ip_p != IPPROTO_UDP)
        return NOT_UDP;

      /* this calculation is incorrect for ipv6 */
      header_len = ip_header->ip_hl * 4;
      udp_header = buff+header_len;
    } else if (ip_header->ip_v == 6){
      struct ip6_hdr *ip6_hdr = buff;
      if( ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
	return NOT_UDP;

      udp_header = buff + sizeof(struct ip6_hdr);
    } else {
      return NOT_IP;
    }

    if( htons(udp_header->uh_dport) != 53)
        return NOT_UDP_53;

    dns = (void *)udp_header + sizeof(struct udphdr);

    if( htons(dns->flags) & 0x8000)
        return NOT_DNS_REQ;

    question = (void *)dns + sizeof(dns_header_t);

    if( is_blacklisted_domain(&(question->name)) )
        return R_DROP;
    if( is_whitelisted_domain(&(question->name)) )
        return R_PASS;

    return R_DROP;
}
