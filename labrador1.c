#include<errno.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<linux/if_ether.h>
#include<linux/ip.h>
#include<linux/if.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<linux/icmp.h>
#include<arpa/inet.h>
#include<string.h>
#include<sys/ioctl.h>
#include<time.h>

void tcpheader_parse(unsigned char *buffer){
	struct tcphdr *tcp_header=(struct tcphdr *)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
	printf("\t------TCP HEADER: LAYER 4-----\n\n\t\t");
	printf("| SOURCE PORT: %d\n\t\t",tcp_header->source);
	printf("| DESTINATION PORT: %d\n\t\t",tcp_header->dest);
	printf("| SEQUENCE NUMBER: %u\n\t\t",tcp_header->seq);
	printf("| ACKNOWLEDGEMENT NUMBER: %u\n\t\t",tcp_header->ack_seq);
	printf("| ----FLAGS----\n\t\t\t| SYN: %u\n\t\t\t| ACK: %u\n\t\t\t| RST: %u\n\t\t\t| PSH: %u\n\t\t\t| FIN: %u\n\t\t\t| URG: %u\n\t\t",tcp_header->syn,tcp_header->ack,tcp_header->rst,tcp_header->psh,tcp_header->fin,tcp_header->urg);
	printf("| WINDOW SIZE: %u\n\t\t", tcp_header->window);
	printf("| CHECKSUM: %u\n\t\t",tcp_header->check);
	printf("| URGENT POINTER: %u\n",tcp_header->urg_ptr);
}

void udpheader_parse(unsigned char *buffer){
	struct udphdr *udp_header=(struct udphdr *)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
	printf("\t-----UDP HEADER: LAYER 4----\n\n\t\t");
	printf("| SOURCE PORT: %d\n\t\t", udp_header->source);
	printf("| DESTINATION PORT: %d\n\t\t",udp_header->dest);
	printf("| LENGTH: %u\n\t\t", udp_header->len);
	printf("| CHECKSUM: %u\n",udp_header->check);
}

void icmpheader_parse(unsigned char *buffer){
	struct icmphdr *icmp_header=(struct icmphdr *)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
	printf("\t-----ICMP HEADER: LAYER 4-----\n\n\t\t ");
	printf("| ICMP TYPE: %d\n\t\t",(unsigned int)icmp_header->type);
	printf("| ICMP CODE: %d\n\t\t", (unsigned int)icmp_header->code);
}

void packet_processor(char *iface){

	struct ifreq ifr;
    	memset(&ifr, 0, sizeof(ifr));

	unsigned int next_layer_proto;
	int socket_handle=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), iface);
	
	if (strcmp(iface,"")!=0){
		int rc=setsockopt(socket_handle, SOL_SOCKET,SO_BINDTODEVICE,iface,sizeof(iface));
		if(rc<0){
			printf("ERROR BINDING SOCKET TO DEVICE");
			printf("%s\n", strerror(errno));
			exit(0);
			}
		else{
			printf("SNIFFING PACKETS ON INTERFACE: %s...\n\n",iface);
			}	
	}
	if(socket_handle<0)
	{
		printf("[x]ERROR CREATING SOCKET. EXITING NOW");
		exit(0);
	}
	struct sockaddr sending_address;
	int sendingaddr_len=sizeof(sending_address);
	//printf("%d %d", socket_address.sa_family,sizeof(socket_address));

	unsigned char *buffer=(unsigned char *)malloc(65536);
	int lenmsg = recvfrom(socket_handle,buffer,65536,0,&sending_address,(socklen_t *)&sendingaddr_len);
	//printf("%s",buffer);
	if(lenmsg<0)
	{
		printf("[x]ERROR RECIEVEING DATA. EXITING NOW");
		exit(0);
	}
	struct ethhdr *e_head= (struct ethhdr*)buffer;
	next_layer_proto=(unsigned int)e_head->h_proto;
	printf("\t-----ETHERNET HEADER: LAYER 2-----\n\n\t\t| SOURCE MAC ADDRESS: %2X:%2X:%2X:%2X:%2X:%2X\n\t\t| DESTINATION MAC ADDRESS: %2X:%2X:%2X:%2X:%2X:%2X\n\t\t| PACKET TYPE: %u\n",e_head->h_source[0],e_head->h_source[1],e_head->h_source[2],e_head->h_source[3],e_head->h_source[4],e_head->h_source[5],e_head->h_dest[0],e_head->h_dest[1],e_head->h_dest[2],e_head->h_dest[3],e_head->h_dest[4],e_head->h_dest[5],e_head->h_proto);

	struct iphdr * ip_head= (struct iphdr*)(buffer+sizeof(struct ethhdr));

	struct sockaddr_in source;
	struct sockaddr_in dest;

	memset(&source,0,sizeof(source));
	memset(&dest,0,sizeof(dest));

	source.sin_addr.s_addr=ip_head->saddr;
	dest.sin_addr.s_addr=ip_head->daddr;
	next_layer_proto=(unsigned int)ip_head->protocol;

	printf("\t-----IP HEADER: LAYER 3-----\n\n\t\t| SOURCE IP ADDRESS: %s\n\t\t", inet_ntoa(source.sin_addr));
	printf("| DESTINATION IP ADDRESS: %s\n\t\t", inet_ntoa(dest.sin_addr));
	printf("| TTL: %u\n\t\t",(unsigned int)ip_head->ttl);
	printf("| CHECKSUM: %d\n\t\t",ntohs(ip_head->check));
	printf("| PROTOCOL: %u\n\t\t",(unsigned int)ip_head->protocol);
	printf("| TYPE OF SERVICE: %u\n\t\t",(unsigned int)ip_head->tos);	
	printf("| INTERNET HEADER LENGTH (IHL): %u\n\t\t",(unsigned int)ip_head->ihl);
	printf("| TOTAL LENGTH: %u\n",ntohs(ip_head->tot_len));

	unsigned int iphdrlen = ip_head->ihl*4;
	struct udphdr *udpobj;
	struct tcphdr *tcpobj;
	struct icmphdr *icmpobj;
	unsigned int tempsize=0;

	if(next_layer_proto==17)
	{
		udpheader_parse(buffer);
		tempsize=sizeof(udpobj);
	}
	else if (next_layer_proto==6)
	{
		tcpheader_parse(buffer);
		tempsize=sizeof(tcpobj);
	}
	else if(next_layer_proto==1)
	{
		icmpheader_parse(buffer);
		tempsize=sizeof(icmpobj);
	}
	else 
	{
		printf("PACKET NOT PARSED!");
	}

/*	unsigned char *data=(unsigned char *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + tempsize);
	printf("%2X",buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + tempsize);
	unsigned int bufflen =65536-((unsigned int)sizeof(struct ethhdr) + (unsigned int)sizeof(struct iphdr) + tempsize);
	printf("\t-----DATA HEXDUMP: LAYER 1-----\n\n");
	printf("%u",bufflen);
	for(int i=0;i<100;++i)
	{
		if(i!=0 && i%16==0){
		printf("%2X",data[i]);}
	}
*/
        printf("\t-----DATA HEXDUMP: LAYER 7-----\n\n");
	unsigned char * data = buffer + iphdrlen  + tempsize;
	int remaining_data = lenmsg - iphdrlen  - tempsize;
 	//printf("REMAING DATA %d\nLENMSG: %d\nSTRUCT IPHDR: %d\nSTRUCT ETHHDR: %d\nSTRUCT TCPHDR: %d\n",remaining_data,(int)sizeof(struct iphdr),(int)sizeof(struct ethhdr),(int)sizeof(struct tcphdr));
	for(int i=0;i<remaining_data;i++)
	{

		if(i!=0 && i%16==0)

			printf("\t %02X ",data[i]);
	}
	printf("\n");

}
int main (int argc, char *argv[]){
	printf("\n██       █████  ██████  ██████   █████  ██████   ██████  ██████  ██    ██  ██\n") ;
	printf("██      ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ ██    ██ ██   ██ ██    ██ ███\n" );
	printf("██      ███████ ██████  ██████  ███████ ██   ██ ██    ██ ██████  ██    ██  ██\n" );
	printf("██      ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ ██    ██ ██   ██  ██  ██   ██\n");
	printf("███████ ██   ██ ██████  ██   ██ ██   ██ ██████   ██████  ██   ██   ████    ██\n");
	if(argc==2){
		printf("\n\nSYNTAX: ./labrador1 <interface name> <time period>\n DEFAULT: Listens on all interfaces for 1 iteration\n");
		packet_processor(argv[1]);
	}	
	else if (argc==1) {
		printf("\n\nSYNTAX: ./labrador1 <interface name> <time period>\n DEFAULT: Listens on all interfaces for 1 iteration\n");
		packet_processor("");	
	
	}
	else if (argc==3) {
		printf("\n\nSYNTAX: ./labrador1 <interface name> <time period>\n DEFAULT: Listens on all interfaces for 1 iteration\n");		
		int msec=0,target=atoi(argv[2]);
		clock_t before = clock();
		int iterations;
		do {
				clock_t difference = clock() - before;
  			msec = difference * 1000 / CLOCKS_PER_SEC;
  			iterations++;		
			packet_processor(argv[1]);
			
			
			}while(msec<target);
		printf("\nTASK COMPLETED IN %d SECONDS %d MILLISECONDS (%d ITERATIONS)\n",msec/1000,msec%1000,iterations);
	}
	
}

