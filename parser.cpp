#include <gtest/gtest.h>
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

void parseAndAssignValueOfField(radio_tap_header_parsed::presence_value &field, const unsigned char *packet){
    using namespace ieee80211_radiotap_field;
    switch(field.presence){
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            struct AntennaSignal val;
            val.signal = convertLe8ToHe((const signed char*)packet);
            field.value = val;
            break;
        //나머지 구현 필요
        //현재 라디오탭에서 signal값만 필요함
        default:
            field.value = false;
    }
}

void parserRadioTapHeader(
        std::vector<radio_tap_header_parsed> &parsed_packets,
        struct pcap_pkthdr* const packet_info,
        const unsigned char** packet
        ){
    const unsigned char* const start_address = *packet;
    
    struct radio_tap_header_parsed current_header;
    current_header.version = *(*packet)++;
    current_header.pad = *(*packet)++;
    current_header.len = convertLeU16ToHe(*packet);
    *(packet) += 2;
    
    uint32_t present_flags;
    do{
    present_flags = convertLeU32ToHe(*packet);
    current_header.present_flags.push_back(present_flags);
    *(packet) += 4;
    }while(parserPresentFlags(&current_header, present_flags));
    
    //Preset flags까지 파싱 완료
    
    class Address{
        private:
            unsigned int _now_relative_address;
            const unsigned char* _start_address;
        public:
            Address(const unsigned char* const start_address, unsigned int now_absolute_address){
                _start_address = start_address;
                _now_relative_address = now_absolute_address;
            }
            void addRelativeAddress(unsigned int operand){
                _now_relative_address += operand;
            }
            const unsigned char *getNowAddress(){
                const unsigned char* now_address = _start_address + _now_relative_address;
                return now_address;
            }
            bool isMultipleOf(int divisor){
                if(divisor == 0)
                    return false;
                return (_now_relative_address % divisor) == 0;
            }
            unsigned int minAdditionForMultipleOf(int divisor){
                if(divisor == 0)
                    return 0;
                return (divisor - (_now_relative_address % divisor));
            }
    };
    Address address(start_address, (unsigned int)((*packet - start_address) / sizeof(char)));
    for(std::vector<radio_tap_header_parsed::presence_value> &fields_of_present_flag : current_header.fields_of_present_flags){
        for(radio_tap_header_parsed::presence_value &field : fields_of_present_flag){
            //필드 순회
            struct flag_align_size_info info_field = _flag_align_size_info[field.presence];
            //address가 align의 배수가 아니라면 align의 배수가 되도록 패딩 건너뜀
            if( !address.isMultipleOf(info_field.align_) ){
                unsigned int padding = address.minAdditionForMultipleOf(info_field.align_);
                address.addRelativeAddress(padding);
            }
            parseAndAssignValueOfField(field, address.getNowAddress());
            address.addRelativeAddress(info_field.size_);
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

#ifdef UNIT_TEST
TEST(ParserRadioTapHeaderTest, HandlesValidInput) {
    std::vector<radio_tap_header_parsed> parsed_packets;
    struct pcap_pkthdr packet_info;
    unsigned char data[] = {0x00 , 0x00 , 0x18 , 0x00 , 0x2e , 0x40 , 0x00 , 0xa0 , 0x20 , 0x08 , 0x00 , 0x00 , 0x00 , 0x02 , 0x6c , 0x09 , 0xa0 , 0x00 , 0xbf , 0x00 , 0x00 , 0x00, 0xbf, 0x00};  // 예제 데이터
    const unsigned char *packet = data;

    parserRadioTapHeader(parsed_packets, &packet_info, &packet);

    
    for(radio_tap_header_parsed &parsed_packet:parsed_packets){
        EXPECT_EQ(parsed_packet.version, 0);
        EXPECT_EQ(parsed_packet.pad, 0);
        EXPECT_EQ(parsed_packet.len, 24);
        EXPECT_EQ(parsed_packet.present_flags.size(), 2);

        if (parsed_packet.present_flags.size() >= 2) {
            // present_flags의 첫 번째 요소가 0xa000402e인지 확인
            EXPECT_EQ(parsed_packet.present_flags[0], 0xa000402e);
            // present_flags의 두 번째 요소가 0x00000820인지 확인
            EXPECT_EQ(parsed_packet.present_flags[1], 0x00000820);
        }
        EXPECT_EQ(std::get<AntennaSignal>(parsed_packet.getValueOfField(0, IEEE80211_RADIOTAP_DB_ANTSIGNAL)).signal, 0xbf);
        EXPECT_EQ(std::get<AntennaSignal>(parsed_packet.getValueOfField(0, IEEE80211_RADIOTAP_DB_ANTSIGNAL)).signal, -65);
        EXPECT_EQ(std::get<AntennaSignal>(parsed_packet.getValueOfField(1, IEEE80211_RADIOTAP_DB_ANTSIGNAL)).signal, 0xbf);
        EXPECT_EQ(std::get<AntennaSignal>(parsed_packet.getValueOfField(1, IEEE80211_RADIOTAP_DB_ANTSIGNAL)).signal, -65);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif