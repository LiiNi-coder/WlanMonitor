#include "pch.h"
#include "ux.h"
#include "packet.h"
//global variables
//std::queue<>
#include <stdio.h>
bool debug_mode = false;

int main(int argc, char* argv[]){
    for(int i = 1; i<argc; i++)
        if(std::string(argv[i]) == "--debug")
            debug_mode = true;

    char errbuf[PCAP_ERRBUF_SIZE];
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
    pcap_descripter = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if(pcap_descripter == NULL)
        HANDLE_ERROR_RETURN_0("pcap_open_live", errbuf);
    
    //const 자료형* 은 포인터 값(=주소값)은 바뀔수있고 포인터가 가리키는 값이 상수가 된다. 자료형* const가 포인터자체가 상수가 되는것이다. 포인터가 가리키는 값은 변경가능
    const unsigned char* packet;
    struct pcap_pkthdr* packet_info;
    struct radiotap_info* current_packet_radio_header = nullptr;
    int i, res;
    while(res = pcap_next_ex(pcap_descripter, &packet_info, &packet)>=0){
        //패킷이 없어서 time out되었음
        if(res==0)
            continue;
        //GUI처리
        
        //패킷 처리
        if(debug_mode)
            printHexOfPacket(packet_info, packet);
        current_packet_radio_header = parserRadioTapHeader(packet_info, &packet);
        //Now, packet is pointing starting of 802.11
    };

    return 0;
}