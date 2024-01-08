#include "pch.h"
#include "parser.h"
#include "ie80211_radiotap.h"
void printHexOfPacket(struct pcap_pkthdr* packet_info, const unsigned char* packet){
    for(int i = 0; i<packet_info->len; i++){
        printf("%02x ", packet[i]);
        if((i+1)%16 == 0)
            printf("\n");
    }
}

void parserRadioTapHeader(struct pcap_pkthdr* const packet_info, const unsigned char** packet);