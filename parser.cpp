#include <gtest/gtest.h>
#include "pch.h"

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
        case IEEE80211_RADIOTAP_TSFT:{
            struct Tsft val;
            val.mactime = convertLeU64ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_FLAGS:{
            struct Flags val;
            val.flags = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_RATE:{
            struct Rate val;
            val.rate = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_CHANNEL:{
            struct Channel val;
            val.frequency = convertLeU16ToHe(packet);
            val.flags = convertLeU16ToHe(packet + 2);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_FHSS:{
            struct Fhss val;
            val.hop_set = convertLeU8ToHe(packet);
            val.hop_pattern = convertLeU8ToHe(packet + 1);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:{
            struct AntennaSignal val;
            val.signal = convertLe8ToHe((const signed char*)packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:{
            struct AntennaNoise val;
            val.noise = convertLe8ToHe((const signed char*)packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_LOCK_QUALITY:{
            struct LockQuality val;
            val.quality = convertLeU16ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_TX_ATTENUATION:{
            struct TxAttenuation val;
            val.attenuation = convertLeU16ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:{
            struct DbTxAttenuation val;
            val.attenuation = convertLeU16ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_DBM_TX_POWER:{
            struct DbmTxPower val;
            val.power = convertLe8ToHe((const signed char*)packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_ANTENNA:{
            struct Antenna val;
            val.antenna = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_DB_ANTSIGNAL:{
            struct DbAntennaSignal val;
            val.signal = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_DB_ANTNOISE:{
            struct DbAntennaNoise val;
            val.noise = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_RX_FLAGS:{
            struct RxFlags val;
            val.flags = convertLeU16ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_TX_FLAGS:{
            struct TxFlags val;
            val.flags = convertLeU16ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_RTS_RETRIES:{
            struct RtsRetries val;
            val.retries = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_DATA_RETRIES:{
            struct DataRetries val;
            val.retries = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_XCHANNEL:{
            struct XChannel val;
            val.flags = convertLeU32ToHe(packet);
            val.freq = convertLeU16ToHe(packet + 4);
            val.channel = convertLeU8ToHe(packet + 6);
            val.maxpower = convertLeU8ToHe(packet + 7);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_MCS:{
            struct Mcs val;
            val.known = convertLeU8ToHe(packet);
            val.flags = convertLeU8ToHe(packet + 1);
            val.mcs = convertLeU8ToHe(packet + 2);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_AMPDU_STATUS:{
            struct AMpdu val;
            val.reference_number = convertLeU32ToHe(packet);
            val.flags = convertLeU16ToHe(packet + 4);
            val.delimiter_CRC_value = convertLeU8ToHe(packet + 6);
            val.reserved = convertLeU8ToHe(packet + 7);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_VHT:{
            struct Vht val;
            val.known = convertLeU16ToHe(packet);
            val.flags = convertLeU8ToHe(packet + 2);
            val.bandwidth = convertLeU8ToHe(packet + 3);
            for(int i = 0; i < 4; i++)
                val.mcs_nss[i] = convertLeU8ToHe(packet + 4 + i);
            val.coding = convertLeU8ToHe(packet + 8);
            val.group_id = convertLeU8ToHe(packet + 9);
            val.partial_aid = convertLeU16ToHe(packet + 10);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_TIMESTAMP:{
            struct Times val;
            val.timestamp = convertLeU64ToHe(packet);
            val.accuracy = convertLeU16ToHe(packet + 8);
            val.unit_position = convertLeU8ToHe(packet + 10);
            val.flags = convertLeU8ToHe(packet + 11);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_HE:{
            struct He val;
            val.data1 = convertLeU16ToHe(packet);
            val.data2 = convertLeU16ToHe(packet + 2);
            val.data3 = convertLeU16ToHe(packet + 4);
            val.data4 = convertLeU16ToHe(packet + 6);
            val.data5 = convertLeU16ToHe(packet + 8);
            val.data6 = convertLeU16ToHe(packet + 10);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_HEMU:{
            struct HeMu val;
            val.flags1 = convertLeU16ToHe(packet);
            val.flags2 = convertLeU16ToHe(packet + 2);
            for(int i = 0; i < 4; i++)
                val.RU_channel1[i] = convertLeU8ToHe(packet + 4 + i);
            for(int i = 0; i < 4; i++)
                val.RU_channel2[i] = convertLeU8ToHe(packet + 8 + i);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_HEMUOTHERUSER:{
            struct HeMuOtherUser val;
            val.per_user_1 = convertLeU16ToHe(packet);
            val.per_user_2 = convertLeU16ToHe(packet + 2);
            val.per_user_position = convertLeU8ToHe(packet + 4);
            val.per_user_known = convertLeU8ToHe(packet + 5);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_ZEROLENGTHPSDU:{
            struct ZeroLengthPsdu val;
            val.type = convertLeU8ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_LSIG:{
            struct LSig val;
            val.data1 = convertLeU16ToHe(packet);
            val.data2 = convertLeU16ToHe(packet + 2);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_TLV:{
            struct Tlv val;
            val.data = convertLeU32ToHe(packet);
            field.value = val;
            break;}
        case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:{
            field.value = false;
            break;}
        case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:{
            struct VendorNamespace val;
            for(int i=0;i<3;i++){
                val.OUI[i] = convertLeU8ToHe(packet + i);
            }
            val.sub_namespace = convertLeU8ToHe(packet + 3);
            val.skip_length = convertLeU16ToHe(packet + 4);
            field.value = val;
            break;}
        default:
            //로직 버그
            std::runtime_error("Present Flag is out of order! : parser.cpp:parseAndAssignValieOfField");
            break;
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

void printRadioTapHeaderParsed(const radio_tap_header_parsed& header) {
    std::cout << "version: " << (int)header.version << std::endl;
    std::cout << "pad: " << (int)header.pad << std::endl;
    std::cout << "len: " << header.len << std::endl;

    std::cout << "present_flags: ";
    for (const auto& flag : header.present_flags) {
        std::cout << flag << " ";
    }
    std::cout << std::endl;

    std::cout << "fields_of_present_flags: " << std::endl;
    for (const auto& fields : header.fields_of_present_flags) {
        for (const auto& field : fields) {
            std::cout << "presence: " << field.presence << ", value: ";

            if (std::holds_alternative<Tsft>(field.value)) {
                Tsft val = std::get<Tsft>(field.value);
                std::cout << "Tsft { mactime: " << val.mactime << " }";
            } else if (std::holds_alternative<Flags>(field.value)) {
                Flags val = std::get<Flags>(field.value);
                std::cout << "Flags { flags: " << (int)val.flags << " }";
            } else if (std::holds_alternative<Rate>(field.value)) {
                Rate val = std::get<Rate>(field.value);
                std::cout << "Rate { rate: " << (int)val.rate << " }";
            } else if (std::holds_alternative<Channel>(field.value)) {
                Channel val = std::get<Channel>(field.value);
                std::cout << "Channel { frequency: " << val.frequency << ", flags: " << val.flags << " }";
            } else if (std::holds_alternative<Fhss>(field.value)) {
                Fhss val = std::get<Fhss>(field.value);
                std::cout << "Fhss { hop_set: " << (int)val.hop_set << ", hop_pattern: " << (int)val.hop_pattern << " }";
            } else if (std::holds_alternative<AntennaSignal>(field.value)) {
                AntennaSignal val = std::get<AntennaSignal>(field.value);
                std::cout << "AntennaSignal { signal: " << (int)val.signal << " }";
            } else if (std::holds_alternative<AntennaNoise>(field.value)) {
                AntennaNoise val = std::get<AntennaNoise>(field.value);
                std::cout << "AntennaNoise { noise: " << (int)val.noise << " }";
            } else if (std::holds_alternative<LockQuality>(field.value)) {
                LockQuality val = std::get<LockQuality>(field.value);
                std::cout << "LockQuality { quality: " << val.quality << " }";
            } else if (std::holds_alternative<TxAttenuation>(field.value)) {
                TxAttenuation val = std::get<TxAttenuation>(field.value);
                std::cout << "TxAttenuation { attenuation: " << val.attenuation << " }";
            } else if (std::holds_alternative<DbTxAttenuation>(field.value)) {
                DbTxAttenuation val = std::get<DbTxAttenuation>(field.value);
                std::cout << "DbTxAttenuation { attenuation: " << val.attenuation << " }";
            } else if (std::holds_alternative<DbmTxPower>(field.value)) {
                DbmTxPower val = std::get<DbmTxPower>(field.value);
                std::cout << "DbmTxPower { power: " << (int)val.power << " }";
            } else if (std::holds_alternative<Antenna>(field.value)) {
                Antenna val = std::get<Antenna>(field.value);
                std::cout << "Antenna { antenna: " << (int)val.antenna << " }";
            } else if (std::holds_alternative<DbAntennaSignal>(field.value)) {
                DbAntennaSignal val = std::get<DbAntennaSignal>(field.value);
                std::cout << "DbAntennaSignal { signal: " << (int)val.signal << " }";
            } else if (std::holds_alternative<DbAntennaNoise>(field.value)) {
                DbAntennaNoise val = std::get<DbAntennaNoise>(field.value);
                std::cout << "DbAntennaNoise { noise: " << (int)val.noise << " }";
            } else if (std::holds_alternative<RxFlags>(field.value)) {
                RxFlags val = std::get<RxFlags>(field.value);
                std::cout << "RxFlags { flags: " << val.flags << " }";
            } else if (std::holds_alternative<TxFlags>(field.value)) {
                TxFlags val = std::get<TxFlags>(field.value);
                std::cout << "TxFlags { flags: " << val.flags << " }";
            } else if (std::holds_alternative<RtsRetries>(field.value)) {
                RtsRetries val = std::get<RtsRetries>(field.value);
                std::cout << "RtsRetries { retries: " << (int)val.retries << " }";
            } else if (std::holds_alternative<DataRetries>(field.value)) {
                DataRetries val = std::get<DataRetries>(field.value);
                std::cout << "DataRetries { retries: " << (int)val.retries << " }";
            } else if (std::holds_alternative<XChannel>(field.value)) {
                XChannel val = std::get<XChannel>(field.value);
                std::cout << "XChannel { flags: " << val.flags << ", freq: " << val.freq << ", channel: " << (int)val.channel << ", maxpower: " << (int)val.maxpower << " }";
            }  else if (std::holds_alternative<Mcs>(field.value)) {
                Mcs val = std::get<Mcs>(field.value);
                std::cout << "Mcs { known: " << (int)val.known << ", flags: " << (int)val.flags << ", mcs: " << (int)val.mcs << " }";
            } else if (std::holds_alternative<AMpdu>(field.value)) {
                AMpdu val = std::get<AMpdu>(field.value);
                std::cout << "AMpdu { reference_number: " << val.reference_number << ", flags: " << val.flags << ", delimiter_CRC_value: " << (int)val.delimiter_CRC_value << ", reserved: " << (int)val.reserved << " }";
            } else if (std::holds_alternative<Vht>(field.value)) {
                Vht val = std::get<Vht>(field.value);
                std::cout << "Vht { known: " << val.known << ", flags: " << (int)val.flags << ", bandwidth: " << (int)val.bandwidth << ", mcs_nss: [";
                for (auto mcs_nss : val.mcs_nss) {
                    std::cout << (int)mcs_nss << " ";
                }
                std::cout << "], coding: " << (int)val.coding << ", group_id: " << (int)val.group_id << ", partial_aid: " << val.partial_aid << " }";
            } else if (std::holds_alternative<Times>(field.value)) {
                Times val = std::get<Times>(field.value);
                std::cout << "Times { timestamp: " << val.timestamp << ", accuracy: " << val.accuracy << ", unit_position: " << (int)val.unit_position << ", flags: " << (int)val.flags << " }";
            } else if (std::holds_alternative<He>(field.value)) {
                He val = std::get<He>(field.value);
                std::cout << "He { data1: " << val.data1 << ", data2: " << val.data2 << ", data3: " << val.data3 << ", data4: " << val.data4 << ", data5: " << val.data5 << ", data6: " << val.data6 << " }";
            } else if (std::holds_alternative<HeMu>(field.value)) {
                HeMu val = std::get<HeMu>(field.value);
                std::cout << "HeMu { flags1: " << val.flags1 << ", flags2: " << val.flags2 << ", RU_channel1: [";
                for (auto RU_channel : val.RU_channel1) {
                    std::cout << (int)RU_channel << " ";
                }
                std::cout << "], RU_channel2: [";
                for (auto RU_channel : val.RU_channel2) {
                    std::cout << (int)RU_channel << " ";
                }
                std::cout << "] }";
            } else if (std::holds_alternative<HeMuOtherUser>(field.value)) {
                HeMuOtherUser val = std::get<HeMuOtherUser>(field.value);
                std::cout << "HeMuOtherUser { per_user_1: " << val.per_user_1 << ", per_user_2: " << val.per_user_2 << ", per_user_position: " << (int)val.per_user_position << ", per_user_known: " << (int)val.per_user_known << " }";
            } else if (std::holds_alternative<ZeroLengthPsdu>(field.value)) {
                ZeroLengthPsdu val = std::get<ZeroLengthPsdu>(field.value);
                std::cout << "ZeroLengthPsdu { type: " << (int)val.type << " }";
            } else if (std::holds_alternative<LSig>(field.value)) {
                LSig val = std::get<LSig>(field.value);
                std::cout << "LSig { data1: " << val.data1 << ", data2: " << val.data2 << " }";
            } else if (std::holds_alternative<Tlv>(field.value)) {
                Tlv val = std::get<Tlv>(field.value);
                std::cout << "Tlv { " << val.data << " }";
            } else if (std::holds_alternative<RadiotapNamespace>(field.value)) {
                RadiotapNamespace val = std::get<RadiotapNamespace>(field.value);
                std::cout << "RadiotapNamespace { }";
            } else if (std::holds_alternative<VendorNamespace>(field.value)) {
                VendorNamespace val = std::get<VendorNamespace>(field.value);
                std::cout << "VendorNamespace { OUI: [";
                for (int i = 0; i < 3; ++i) {
                    std::cout << (int)val.OUI[i] << " ";
                }
                std::cout << "], sub_namespace: " << (int)val.sub_namespace << ", skip_length: " << val.skip_length << " }";
            } else {
                std::cout << "Unknown type";
            }
            std::cout << std::endl;
        }
    }
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