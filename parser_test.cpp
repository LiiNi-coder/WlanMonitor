// parser_test.cpp
#ifdef UNIT_TEST
#include <gtest/gtest.h>
#include "pch.h"
#include "ie80211_radiotap.h"
#include "parser.h"
TEST(ParserRadioTapHeaderTest, HandlesValidInput) {
    std::vector<radio_tap_header_parsed> parsed_packets;
    struct pcap_pkthdr packet_info;
    unsigned char data[] = {0x01, 0x02, 0x18, 0x00};  // 예제 데이터
    const unsigned char* packet = data;

    parserRadioTapHeader(parsed_packets, &packet_info, &packet);

    ASSERT_EQ(parsed_packets.size(), 1);
    EXPECT_EQ(parsed_packets[0].version, 0x01);
    EXPECT_EQ(parsed_packets[0].pad, 0x02);
    EXPECT_EQ(parsed_packets[0].len, 24);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif