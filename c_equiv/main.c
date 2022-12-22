#include <stdio.h>
#include <sys/types.h>
#include "tcpip.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    pcap_t *handle;		/* Session handle */
    char *dev = argv[1];		/* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "port 23";	/* The filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    pcap_loop(handle,-1,got_packet,NULL);
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    const struct sniff_ethernet* eth;
    const struct sniff_ip* ip;
    const struct sniff_tcp* tcp;
    const char* payload;
    u_int8_t size_ip;
    u_int8_t size_tcp;
    eth = (struct sniff_ethernet*) (packet);
    ip = (struct sniff_ip*)  (packet + ETHER_SIZE);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20){
        fprintf(stderr,"ip header invalid length");
        return;
    }
    tcp = (struct sniff_tcp*) (packet + ETHER_SIZE + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if(size_tcp < 20){
        fprintf(stderr,"tcp header invalid length");
        return;
    }
    payload = (char*) (packet+ETHER_SIZE+size_ip+size_tcp);
    printf("%s\n",payload);
    printf("%s\n",ip->ip_dst.s_addr);
}
