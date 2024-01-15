#include "pch.h"
#include "ie80211_radiotap.h"
#include "parser.h"
void printHexOfPacket(struct pcap_pkthdr* packet_info, const unsigned char* packet){
    for(int i = 0; i<packet_info->len; i++){
        printf("%02x ", packet[i]);
        if((i+1)%16 == 0)
            printf("\n");
    }
}

void parserRadioTapHeader(
        std::vector<radio_tap_header_parsed> &parsed_packets,
        struct pcap_pkthdr* const packet_info,
        const unsigned char** packet
        ){
    const unsigned char** start_address = packet;
    
    struct radio_tap_header_parsed current_header;
    current_header.version = *(*packet)++;
    current_header.pad = *(*packet)++;
    current_header.len = convertLe16ToHe(*packet);
    *(packet) += 2;
    
    do{
    uint32_t present_flags = convertLe32ToHe(*packet);
    current_header.present_flags.push_back(present_flags);
    *(packet) += 4;
    }while(parserPresentFlags(&current_header, present_flags));
    
    //Preset flags까지 파싱 완료

    class Z16Z {
        private:
            int value;
        public:
            Z16Z(int val) {
                value = val % 16;
            }
            Z16Z operator+(const int& rhs) {
                return Z16Z((this->value + rhs) % 16);
            }
            Z16Z& operator=(const int& rhs) {
                this->value = rhs % 16;
                return *this;
            }
            operator int() const {
                return value;
            }
            // 값이 인자의 배수인지 확인하는 메소드
            bool isMultipleOf(int divisor) {
                if(divisor == 0) return false; // 0으로 나눌 경우 false 반환
                return value % divisor == 0;
            }
            // 값이 인자의 배수가 되기 위해 필요한 최소 추가값을 반환하는 메소드
            int minAdditionForMultipleOf(int divisor) {
                if(divisor == 0) return -1; // 0으로 나눌 경우 -1 반환
                return (divisor - (value % divisor)) % divisor;
            }
    };
    /**
     * @brief 패킷에서 현재 가리키고 있는 주소(단 Z/16Z형태) 
     */
    Z16Z address(int((*(packet) - *(packet)) / sizeof(char)*8));
    for(std::vector<radio_tap_header_parsed::presence_value> &fields_of_present_flag : current_header.fields_of_present_flags){
        for(radio_tap_header_parsed::presence_value &field : fields_of_present_flag){
            //필드 순회
            struct AlignSizeInfo info_field = _alignSizeInfo[field.presence];
            //address가 align의 배수가 아니라면
            if(!address.isMultipleOf(info_field.align_)){
                int padding = address.minAdditionForMultipleOf(info_field.align_);
                address = address + padding;
                
            }
        }
    }


    parsed_packets.push_back(current_header);
}

bool parserPresentFlags(struct radio_tap_header_parsed *current_header, uint32_t present_flags){
    uint32_t mask;
    std::vector<radio_tap_header_parsed::presence_value> fields_of_present_flag;
    for(int i = 0; i < 31; i++){
        mask = getMaskRadiotapPresence(i);
        if((present_flags & mask) == mask){
            radio_tap_header_parsed::presence_value present_flag_presence;
            present_flag_presence.presence = static_cast<ieee80211_radiotap_presence>(i);
            fields_of_present_flag.push_back(present_flag_presence);
        }
    }
    current_header->fields_of_present_flags.push_back(fields_of_present_flag);
    mask = getMaskRadiotapPresence(31);
    return ((present_flags & mask) == mask);
}