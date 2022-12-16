#include <pcap.h>
#include <pcap/pcap.h>
int main(){
    pcap_if_t *devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&devices,errbuf);
    printf("%s\n",devices[0].name);
    pcap_handle()
}
