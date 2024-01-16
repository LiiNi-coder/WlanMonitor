// parser_test.cpp
#ifdef UNIT_TEST
#include <gtest/gtest.h>
#include "pch.h"

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
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif