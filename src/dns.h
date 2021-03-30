#ifndef __H_DNS__
#define __H_DNS__

#include <stdint.h>
#include <stdlib.h>

#define DNSMAX 512
#define NAMEMAX 10
#define DNSPORT 53

#define NPTRMSK 0xC0
typedef struct {
	unsigned char length;
	unsigned char *data;
} dns_name_label;

#define ATYPE 1
#define NSTYPE 2
#define CNAMETYPE 5
#define INCLS 1
typedef struct {
	dns_name_label *name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	unsigned char *rdata;
} dns_resource;

typedef struct {
	dns_name_label *qname;
	uint16_t qtype;
	uint16_t qclass;
} dns_question;

#define QRMSK	1 << 15
#define OPMSK	1111 << 11
#define AAMSK	1 << 10
#define TCMSK	1 << 9
#define RDMSK	1 << 8
#define RAMSK	1 << 7
#define ZMSK	111 << 4
#define RMSK	1111
typedef struct {
	uint16_t id;
	uint16_t params;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} dns_header;

typedef struct {
	dns_header header;
	dns_question *question;
	dns_resource *answer;
	dns_resource *authority;
	dns_resource *additional;
} dns_message;

dns_question *malloc_dns_question();

// domainstr is modified by modification on dest's data
// is it important ?
void strtoname(dns_name_label *dest, char *namestr);

void nametostr(dns_name_label *src, char *namestr);

// Setup dns_header struct for a one question query
void new_qheader(dns_header *dest);

// Setup dns_question struct for a A IN dns query
void new_aquestion(dns_question *dest, dns_name_label *name);

// Creates a simple IN A question query dns_message
dns_message new_qmessage(dns_question *question);

unsigned char *msgtoraw(unsigned char *dest, dns_message *msg);
void rawtomsg(unsigned char *src, dns_message *dest);

unsigned char *rawtoname(unsigned char *src, dns_name_label *name, unsigned char *packet);
#endif
