#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#define	ETHERTYPE_PUP	0x0200		/* PUP protocol */
#define	ETHERTYPE_IP	0x0800		/* IP protocol */
#define ETHERTYPE_ARP	0x0806		/* Addr. resolution protocol */
//[출처] http://minirighi.sourceforge.net/html/arp_8h-source.html
// 실제 헤더와 일치함을 알 수 있습니다.
struct arp
{
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
	uint8_t  arp_eth_source[6];
	//! IP source address.
	uint32_t arp_ip_source;
	//! Hardware destination address.
	uint8_t  arp_eth_dest[6];
	//! IP destination address.
	uint32_t arp_ip_dest;
};




int main(int argc, char *argv[])
{
	int flag , i;
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	struct ip *iphdr; 
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr* header;	/* The header that pcap gives us */
	struct arp *m_arp = (struct arp *)malloc(sizeof(m_arp));

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
	m_arp->arp_hard_type = htons(0x0001);
	m_arp->arp_proto_type = htons(ETHERTYPE_ARP);
	m_arp->arp_hard_size = 0x06;
	m_arp->arp_proto_size = 0x40;
	m_arp->arp_oper = htons(0x0010);
	temp = "005056ee669d";
	for (i = (sizeof(temp) / 2) - 1 ; i >= 0; i--)
	{
		
	}
	
	memcpy(m_arp->arp_eth_source ,temp ,6);
	m_arp->arp_ip_source = htonl(0xc0a8ca02);
	temp = "000000000000";
	memcpy(m_arp->arp_eth_dest , temp, 6);
	m_arp->arp_ip_dest = htonl(0xc0a8ca9b);
	//printf("%d",sizeof(m_arp));
	pcap_sendpacket(handle ,(u_char *)m_arp , sizeof(m_arp));


	printf("error\n");
	/* Grab a packet */
	while((flag = pcap_next_ex(handle, &header,&packet)) >= 0)
	{
		if(!flag)//flag == 0 (timeout)d
			continue;
		temp = packet + 14;
		iphdr = (struct ip*) temp; 
		if(iphdr->ip_p == ETHERTYPE_ARP)//ARP
			continue;

		//packet = pcap_next(handle, &header);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header->len);
		/* And close the session */
		pcap_close(handle);
	}
	return(0);
}
