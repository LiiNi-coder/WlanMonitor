#include "pch.h"
#include "ux.h"
//global variables
//std::queue<>

bool debug_mode = false;

int main(int argc, char* argv[]){
    for(int i = 1; i<argc; i++)
        if(std::string(argv[i]) == "--debug")
            debug_mode = true;

    char errbuf[PCAP_ERRBUF_SIZE];
    std::string interface_name;
    pcap_t *pcap_descripter;

    USE_ALTERNATE_BUFFER();
    printFirstDescribe();
    interface_name = getInterfaceUserChoice();
    CLEAR_SCREEN();
    DEBUG_VAR(interface_name);
    /**
     * 네트워크 인터페이스 interface_name에 대한 패킷을 캡처하는 디스크립트 반환
     * (네트워크 인터페이스, 받아들일수 있는 패킷 최대크기, promiscuous mode여부, 읽기 시간 초과, 에러버프)
    */
    pcap_descripter = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    //패킷을 저장하는 생산쓰레드 생성

    //패킷을 분석하는 소비쓰레드 생성
    return 0;
}