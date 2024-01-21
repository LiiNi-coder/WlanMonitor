#include "pch.h"

bool debug_mode = false;
int main(int argc, char* argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    for(int i = 1; i<argc; i++)
        std::string argument = std::string(argv[i]);
        if(argument == "--debug")
            debug_mode = true;
    if(std::string(argv[0]).find("beacon-flood") != std::string::npos){
        if(argc != 3){
            puts("Usage : beacon-flood <interface> <ssid-list-file>");
            HANDLE_ERROR_EXIT_0("main", errbuf);
        }
        beaconFlood(std::string(argv[1]), std::string(argv[2]));
        exit(0);
    }
    std::string interface_name;
    pcap_t *pcap_descripter;
    //USE_ALTERNATE_BUFFER();
    printFirstDescribe();
    interface_name = getInterfaceUserChoice();
    //CLEAR_SCREEN();
    DEBUG_VAR(interface_name);
    /**
     * 네트워크 인터페이스 interface_name에 대한 패킷을 캡처하는 디스크립트 반환
     * (네트워크 인터페이스, 받아들일수 있는 패킷 최대크기, promiscuous mode여부, 읽기 시간 초과, 에러버프)
    */
  #ifdef OFFLINE
    pcap_descripter = pcap_open_offline("80211packet_iptimeN150UA2.pcapng.pcap", errbuf);
  #else
    pcap_descripter = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
  #endif
    if(pcap_descripter == NULL)
        HANDLE_ERROR_RETURN_0("pcap_open_live", errbuf);
    
    //const 자료형* 은 포인터 값(=주소값)은 바뀔수있고 포인터가 가리키는 값이 상수가 된다. 자료형* const가 포인터자체가 상수가 되는것이다. 포인터가 가리키는 값은 변경가능
    const unsigned char* packet;
    struct pcap_pkthdr* packet_info;
    struct radiotap_info* current_packet_radio_header = nullptr;
    int i, res;
    std::vector<radio_tap_header_parsed> parsed_packets;
    while(res = pcap_next_ex(pcap_descripter, &packet_info, &packet)>=0){
        //패킷이 없어서 time out되었음
        if(res==0)
            break;
        //GUI처리
        
        //패킷 처리
        if(debug_mode)
            printHexOfPacket(packet_info, packet);
        
        parserRadioTapHeader(parsed_packets, packet_info, &packet);
        //Now, packet is pointing starting of 802.11
    };

    //시각화
    for(radio_tap_header_parsed parsed_packet : parsed_packets){
        printRadioTapHeaderParsed(parsed_packet);
    }

    pcap_close(pcap_descripter);
    return 0;
}