#include "dns.h"

//=====================MALLOC=====================================
//================================================================
dns_resource *malloc_dns_resources(int len) {
	int size_name = sizeof(dns_name_label) * NAMEMAX;
	int size_res = sizeof(dns_resource);
	int total = (size_name + size_res) * len;

	// malloc dns_resource array + dns_names space
	void *mem = malloc(total);
	void *end = mem + total;

	// assign one dns_name space per dns_resource
	dns_resource *res = (dns_resource *) mem;
	for(int i = 0 ; i < len ; i++) {
		int offset = size_name * (i+1);
		res[i].name = (dns_name_label *) (end - offset);
	}
	return res;
}

dns_question *malloc_dns_question() {
	int size_name = sizeof(dns_name_label) * NAMEMAX;
	int size_quest = sizeof(dns_question);
	int total = size_name + size_quest;

	void *mem = malloc(total);
	void *end = mem + total;

	dns_question *quest = (dns_question *) mem;
	quest->qname = (dns_name_label *) (end - size_name);
	return quest;
}
//================================================================
//================================================================

//=========================XXXTORAW===============================
//================================================================
// fills dest with the raw two byte int and returns a pointer to the next address
unsigned char *dinttoraw(unsigned char *dest, uint16_t n) {
	dest[0] = (n >> 8);
	dest[1] = n;
	return dest+2;
}

// fills dest with the raw four byte int and returns a pointer to the next address
unsigned char *qinttoraw(unsigned char *dest, uint32_t n) {
	dest[0] = (n >> 24);
	dest[1] = (n >> 16);
	dest[2] = (n >> 8);
	dest[3] = n;
	return dest+4;
}

// fills dest with the raw header and returns a pointer to the next address
unsigned char *headertoraw(unsigned char *dest, dns_header *header) {
	dest = dinttoraw(dest, header->id);
	dest = dinttoraw(dest, header->params);
	dest = dinttoraw(dest, header->qdcount);
	dest = dinttoraw(dest, header->ancount);
	dest = dinttoraw(dest, header->nscount);
	dest = dinttoraw(dest, header->arcount);
	return dest;
}

// fills dest with the raw label bytes and returns a pointer to the next address
unsigned char *labtoraw(unsigned char *dest, unsigned char *lab, unsigned char length) {
	for (int i = 0 ; i < length ; i++) {
		*dest = lab[i];
		dest++;
	}
	return dest;
}

// fills dest with the raw name and returns a pointer to the next address
unsigned char *nametoraw(unsigned char *dest, dns_name_label *name) {
	int end = 0;
	while (!end) {
		*dest = name->length;
		dest = labtoraw(dest+1, name->data, name->length);
		end = name->length == 0;
		name++;
	} 
	return dest;
}

// fills dest with the raw question and returns a pointer to the next address
unsigned char *questtoraw(unsigned char *dest, dns_question *question) {
	dest = nametoraw(dest, question->qname);
	dest = dinttoraw(dest, question->qtype);
	dest = dinttoraw(dest, question->qclass);
	return dest;
}

// fills dest with the raw dns message and returns a pointer to the next address
unsigned char *msgtoraw(unsigned char *dest, dns_message *msg) {
	dest = headertoraw(dest, &(msg->header));

	for (int i = 0 ; i < msg->header.qdcount ; i++) {
		dest = questtoraw(dest, msg->question+i);
	}

	// IS DEALING WITH THE RESOURCES (ANSWER ...) IMPORTANT FOR OUR IMPLEMENTATION ? //
	return dest;
}
//================================================================
//================================================================

//===============================RAWTOXXX=========================
//================================================================
unsigned char *rawtodint(unsigned char *src, uint16_t *n) {
	*n = src[0] << 8 | src[1];
	return src+2;
}

unsigned char *rawtoqint(unsigned char *src, uint32_t *n) {
	*n = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3];
	return src+4;
}

int name_ptr_offset(unsigned char *src) {
	int ret = -1;

	// is a name pointer
	if (*src & NPTRMSK) {
		ret = (src[0] & ~NPTRMSK) << 8 | src[1];
	}

	return ret;
}

// requires an other pointer from the start of the packet for name pointing
unsigned char *rawtoname(unsigned char *src, dns_name_label *name, unsigned char *packet) {
	while (*src != 0) {
		int offset = name_ptr_offset(src);
		if (offset != -1) {
			rawtoname(packet+offset, name, packet);
			return src+2;
		}

		name->length = *src;
		name->data = src+1;
		src += 1 + name->length;
		name++;
	}

	name->length = 0;
	name->data = 0;
	return src + 1;
}

// requires an other pointer from the start of the packet for name pointing
unsigned char *rawtoquest(unsigned char *src, dns_question *question, unsigned char *packet) {
	src = rawtoname(src, question->qname, packet);
	src = rawtodint(src, &question->qtype);
	src = rawtodint(src, &question->qclass);
	return src;
}

unsigned char *rawtoheader(unsigned char *src, dns_header *header) {
	src = rawtodint(src, &header->id);
	src = rawtodint(src, &header->params);
	src = rawtodint(src, &header->qdcount);
	src = rawtodint(src, &header->ancount);
	src = rawtodint(src, &header->nscount);
	src = rawtodint(src, &header->arcount);
	return src;
}

// requires an other pointer from the start of the packet for name pointing
unsigned char *rawtoresource(unsigned char *src, dns_resource *resource, unsigned char *packet) {
	src = rawtoname(src, resource->name, packet);
	src = rawtodint(src, &resource->type);
	src = rawtodint(src, &resource->class);
	src = rawtoqint(src, &resource->ttl);
	src = rawtodint(src, &resource->rdlength);
	
	resource->rdata = src;
	
	return src + resource->rdlength;
}

// requires an other pointer from the start of the packet for name pointing
unsigned char *rawtoresources(unsigned char *src, dns_resource **dest, uint16_t len, unsigned char *packet) {
	*dest = malloc_dns_resources(len);
	for (int i = 0 ; i < len ; i++) {
		src = rawtoresource(src, *dest+i, packet);
	}
	return src;
}

void rawtomsg(unsigned char *src, dns_message *msg) {
	unsigned char *packet = src;
	src = rawtoheader(src, &msg->header);

	for (int i = 0 ; i < msg->header.qdcount ; i++) {
		src = rawtoquest(src, msg->question+i, packet);
	}

	src = rawtoresources(src, &msg->answer, msg->header.ancount, packet);
	src = rawtoresources(src, &msg->authority, msg->header.nscount, packet);
	src = rawtoresources(src, &msg->additional, msg->header.arcount, packet);
}
//================================================================
//================================================================

//===========================NAME STR=============================
//================================================================
int is_domain_sep(char c) {
	return c == '.' || c == '\0';
}

// domainstr is modified by modification on dest's data, is it important ?
void strtoname(dns_name_label *dest, char *namestr) {
	char *start = namestr;
	int end = 0;
	while (!end) {
		if (is_domain_sep(*namestr)) {
			dest->data = (unsigned char *) start;
			dest->length = namestr - start;

			start = namestr + 1;
			end = *namestr == '\0';
			dest++;
		}

		namestr++;
	}

	dest->length = 0;
	dest->data = 0;
}

void nametostr(dns_name_label *src, char *namestr) {
	while(src->length != 0) {
		for (int i = 0 ; i < src->length ; i++) {
			*namestr = src->data[i];
			namestr++;
		}
		
		src++;
		if (src->length != 0) {
			*namestr = '.';
			namestr++;
		}
	}

	*namestr = '\0';
}
//================================================================
//================================================================

//=============================CREATE=============================
//================================================================
// Setups dns_header for a one question query
void new_qheader(dns_header *dest) {
	dest->id = 0xBEBE;
	dest->params = 0;
	dest->params |= RDMSK;
	dest->qdcount = 1;
	dest->ancount = 0;
	dest->nscount = 0;
	dest->arcount = 0;
}

// Setups dns_question for a A IN dns query
void new_aquestion(dns_question *dest, dns_name_label *domainname) {
	dest->qname = domainname;
	dest->qtype = ATYPE;
	dest->qclass = INCLS;
}

// Creates a simple IN A question query dns_message
dns_message new_qmessage(dns_question *question) {
	dns_message rtn;
	new_qheader(&rtn.header);
	rtn.question = question;
	return rtn;
}
//================================================================
//================================================================
