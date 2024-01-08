#include <variant>
struct radio_tap_header_parsed{
    uint8_t        version;     /* set to 0 */
    uint8_t        pad;
    uint16_t       len;
    std::vector<uint32_t> present_flags;
    bool isValidPresentFlag(uint32_t present_flag, enum ieee80211_radiotap_presence target){
        // TO DO
    };
    // TO DO
    //std::vector<std::variant<>> fields_of_first_present_flag;
    
};

void printHexOfPacket(struct pcap_pkthdr* const packet_info, const unsigned char* packet);
/**
 * @brief 패킷된 pcap인덱스를 통해 파싱을 하고 파싱된 radio tap Header 정보를 반환
 * 
 * @param packet_info pcap패킷 정보
 * @param packet pcap인덱스; radio tap header를 가리키고 있어야함
 */
void parserRadioTapHeader(struct pcap_pkthdr* const packet_info, const unsigned char** packet);

