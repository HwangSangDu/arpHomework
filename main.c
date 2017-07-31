#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netinet/ether.h>
#define	ETHERTYPE_PUP	0x0200		/* PUP protocol */
#define	ETHERTYPE_IP	0x0800		/* IP protocol */
#define ETHERTYPE_ARP	0x0806		/* Addr. resolution protocol */
//[출처] http://minirighi.sourceforge.net/html/arp_8h-source.html
// 실제 헤더와 일치함을 알 수 있습니다.


struct arp
{
	struct ethhdr eth; 
	//! Format of hardware address.
	uint16_t arp_hard_type;
	//! Format of protocol address.
	uint16_t arp_proto_type;
	//! Length of hardware address.
	uint8_t  arp_hard_size;
	//! Length of protocol address.
	uint8_t  arp_proto_size;
	//! ARP operation code (command).
	uint16_t arp_oper;
	//! Hardware source address.
	u_char	  arp_eth_source[6];
	//! IP source address.
	u_char	 arp_ip_source[4];
	//! Hardware destination address.
	u_char	  arp_eth_dest[6];
	//! IP destination address.
	u_char	 arp_ip_dest[4];
};




int main(int argc, char *argv[])
{
	int flag , i;
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	struct ethhdr *ethhdr; 
	struct ip *iphdr; 
	char filter_exp[] = "arp";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr* header;	/* The header that pcap gives us */
	struct arp *m_arp = (struct arp *)malloc(sizeof(m_arp));
	struct arp *recv_arp = (struct arp *)malloc(sizeof(m_arp));

	const u_char *temp;
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	//[참조] https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut8.html
	/*
	uint16_t arp_hard_type;
	uint16_t arp_proto_type;
	uint8_t  arp_hard_size;
	uint8_t  arp_proto_size;
	uint16_t arp_oper;
	uint8_t  arp_eth_source[6];
	uint32_t arp_ip_source;
	uint8_t  arp_eth_dest[6];
	uint32_t arp_ip_dest;
	//*/
	memcpy(m_arp->eth.h_dest,"\xff\xff\xff\xff\xff\xff",6);
	memcpy(m_arp->eth.h_source,"\x00\x0c\x29\x79\xa8\x03",6);
	m_arp->eth.h_proto = htons(ETHERTYPE_ARP);

	m_arp->arp_hard_type = htons(0x0001);
	m_arp->arp_proto_type = htons(ETHERTYPE_IP);
	m_arp->arp_hard_size = 0x06;
	m_arp->arp_proto_size = 0x04;
	m_arp->arp_oper = htons(0x0001);
	//temp = "\x00\x50\x56\xee\x66\x9d";
	memcpy(m_arp->arp_eth_source ,"\x00\x0c\x29\x79\xa8\x03",6);
	/*
	m_arp->arp_eth_source[0] = 0x00;
	m_arp->arp_eth_source[1] = 0x50;
	m_arp->arp_eth_source[2] = 0x56;
	m_arp->arp_eth_source[3] = 0xee;
	m_arp->arp_eth_source[4] = 0x66;
	m_arp->arp_eth_source[5] = 0x9d;
	//*/
	//memcpy(m_arp->arp_eth_source ,temp ,6);
	//m_arp->arp_ip_source = htonl(0xc0a8ca02);
	memcpy(m_arp->arp_ip_source , "\xc0\xa8\xca\x9b",4);

	memcpy (m_arp->arp_eth_dest,"\x00\x00\x00\x00\x00\x00",6);
	//memcpy(m_arp->arp_eth_dest , temp, 6);
	memcpy(m_arp->arp_ip_dest,"\xc0\xa8\xca\x02",4);
	//printf("%d",sizeof(m_arp));
	pcap_sendpacket(handle ,(u_char *)m_arp , 42);



	
	/* Grab a packet */
	while((flag = pcap_next_ex(handle, &header,&packet)) >= 0)
	{
		if(!flag)//flag == 0 (timeout)
			continue;
		//recv_arp->eth = (struct ethhdr *) packet; 
		//memcpy(&recv_arp->eth , packet , sizeof(packet));

		ethhdr = (struct ethhdr *) packet;
		//memcpy(&recv_arp->eth , ethhdr , sizeof(packet));
		recv_arp->eth = *ethhdr;
		if(ntohs(recv_arp->eth.h_proto) != ETHERTYPE_ARP)
			continue;
		printf("DEST MAC=%s\n",ether_ntoa((struct ether_addr *) recv_arp->eth.h_dest));
		printf("SRC  MAC=%s\n",ether_ntoa((struct ether_addr *) recv_arp->eth.h_source));
		printf("PROTOCOL=%04x\n",ntohs(recv_arp->eth.h_proto));

		temp = packet + 14;
		iphdr = (struct ip*) temp; 
		if(iphdr->ip_p != ETHERTYPE_IP)//ARP
			continue;

		//packet = pcap_next(handle, &header);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header->len);
		/* And close the session */
		pcap_close(handle);
	}
	return(0);
}
