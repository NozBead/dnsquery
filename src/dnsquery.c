#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns.h"

//============================PRINTING============================
//================================================================
int find_ip(char *dest, dns_message *msg) {
	for (int i = 0 ; i < msg->header.ancount ; i++) {
		dns_resource answer = msg->answer[i];
		if (answer.type == ATYPE) {
			sprintf(dest, "%d.%d.%d.%d",
				answer.rdata[0], answer.rdata[1], answer.rdata[2], answer.rdata[3]);
			return 0;
		}
	}

	return -1;
}

void typetostr(uint16_t type, char *dest) {
	switch(type) {
		case ATYPE :
			sprintf(dest, "A");
		break;

		case CNAMETYPE : 
			sprintf(dest, "CNAME");
		break;

		case NSTYPE :
			sprintf(dest, "NS");
		break;

		default :
			sprintf(dest, "KO");
	}
}

void classtostr(uint16_t class, char *dest) {
	switch(class) {
		case INCLS :
			sprintf(dest, "IN");
		break;

		default :
			sprintf(dest, "KO");
	}
}

void rdatatostr(uint16_t type, unsigned char *rdata, char *dest, unsigned char *packet) {
	dns_name_label name[NAMEMAX];
	char namestr[64];

	switch(type) {
		case ATYPE :
			sprintf(dest, "%d.%d.%d.%d",
				rdata[0], rdata[1], rdata[2], rdata[3]);
		break;

		case CNAMETYPE :
			rawtoname(rdata, name, packet);
			nametostr(name, namestr);
			sprintf(dest, "%s", namestr);
		break;

		case NSTYPE :
			rawtoname(rdata, name, packet);
			nametostr(name, namestr);
			sprintf(dest, "%s", namestr);
		break;

		default :
			sprintf(dest, "UNKNOWN DATA");
	}
}

void print_dns_resources(dns_resource *res, int count, unsigned char *packet) {
	char name[64];
	char type[8];
	char class[4];
	char rdata[64];

	for (int i = 0 ; i < count ; i++) {
		nametostr(res[i].name, name);
		typetostr(res[i].type, type);
		classtostr(res[i].class, class);
		rdatatostr(res[i].type, res[i].rdata, rdata, packet);

		printf(	"%s %s %s %s\n",
			name, class, type, rdata);
			
	}
}

void print_dns_questions(dns_question *quest, int count) {
	char name[64];
	char type[8];
	char class[4];

	for (int i = 0 ; i < count ; i++) {
		nametostr(quest[i].qname, name);
		typetostr(quest[i].qtype, type);
		classtostr(quest[i].qclass, class);

		printf(	"%s %s %s\n",
			name, class, type);
	}
}

void print_dns_response(dns_message *msg, unsigned char *packet) {
	if (msg->header.qdcount != 0) {
		printf("\tQuestions\n");
		print_dns_questions(msg->question, msg->header.qdcount);
	}
	if (msg->header.ancount != 0) {
		printf("\n\tAnswers\n");
		print_dns_resources(msg->answer, msg->header.ancount, packet);
	}
	if (msg->header.nscount != 0) {
		printf("\n\tAuthorities\n");
		print_dns_resources(msg->authority, msg->header.nscount, packet);
	}
	if (msg->header.arcount != 0) {
		printf("\n\tAdditionals\n");
		print_dns_resources(msg->additional, msg->header.arcount, packet);
	}
}
//================================================================
//================================================================

//========================== NETWORK =============================
//================================================================
int fillsockaddr(struct sockaddr_in *addr, const char *ip, int port) {
	int retval = 0;
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	if (inet_aton(ip, &addr->sin_addr) == 0) {
		fprintf(stderr, "Error interpreting IP : %s\n", ip);
		retval = -1;
	}
	return retval;
}

int query_server(const char *ip, int port, unsigned char *udp_payload, int len) {
	struct sockaddr_in addr;
	socklen_t sock_len = sizeof(addr);

	if (fillsockaddr(&addr, ip, port) == -1) {
		return -1;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("Error allocating socket");
		return -1;
	}

	int err = sendto(sock, udp_payload, len, 0, (struct sockaddr *)&addr, sock_len);
	if (err == -1) {
		perror("Error sending packet");
		return -1;
	}
	
	err = recvfrom(sock, udp_payload, DNSMAX, 0, (struct sockaddr *)&addr, &sock_len);
	if (err == -1) {
		perror("Error recieving response");
		return -1;
	}

	return err;
}
//================================================================
//================================================================

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Usage : %s hostname dns_server_ip\n", argv[0]);
		return 1;
	}

	dns_question *question = malloc_dns_question();

	strtoname(question->qname, argv[1]);
	new_aquestion(question, question->qname);

	dns_message msg = new_qmessage(question);

	unsigned char udp_payload[DNSMAX];
	int msg_len = msgtoraw(udp_payload, &msg) - udp_payload;
	if (query_server(argv[2], DNSPORT, udp_payload, msg_len) == -1) {
		return 2;
	}
	
	rawtomsg(udp_payload, &msg);
	print_dns_response(&msg, udp_payload);

	char ipstr[16];
	if (find_ip(ipstr, &msg) == -1) {
		fprintf(stderr, "\n\nIPv4 not found for %s\n", argv[1]);
	}
	else {
		fprintf(stderr, "\n\nThe IPv4 behind %s is %s\n", argv[1], ipstr);
	}
	
		
	free(msg.question);
	free(msg.answer);
	free(msg.authority);
	free(msg.additional);

	return 0;
}
