#include <variant>
#include <endian.h>
//Le = LittleEndian, He = HostEndian
inline uint8_t convertLeU8ToHe(const unsigned char* target){
    uint8_t var = target[0];
    return var;
}
inline int8_t convertLe8ToHe(const signed char* target){
    int8_t var = target[0];
    return var;
}
inline uint16_t convertLeU16ToHe(const unsigned char* target) {
    uint16_t var;
    uint16_t temp = target[0] | (target[1] << 8);
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        var = temp;
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        var = (temp >> 8) | (temp << 8);
    #else
        #error "Unknown endianness"
    #endif
    return var;
}

inline int16_t convertLe16ToHe(const unsigned char* target) {
    int16_t var;
    int16_t temp = target[0] | (target[1] << 8);
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        var = temp;
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        var = (temp >> 8) | (temp << 8);
    #else
        #error "Unknown endianness"
    #endif
    return var;
}

inline uint32_t convertLeU32ToHe(const unsigned char* target) {
    uint32_t var;
    uint32_t temp = target[0] | (target[1] << 8) | (target[2] << 16) | (target[3] << 24);
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        // 리틀 엔디안 시스템에서는 패킷을 그대로 복사합니다.
        var = temp;
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 빅 엔디안 시스템에서는 바이트 순서를 바꿉니다.
        var = (temp >> 24) | ((temp & 0x00FF0000) >> 8) | ((temp & 0x0000FF00) << 8) | (temp << 24);
    #else
        #error "Unknown endianness"
    #endif
    return var;
}

//출처 : https://gitlab.com/gilgil/
struct flag_align_size_info {
	int size_;
	int align_;
} _flag_align_size_info[] {
	{8, 8}, // 0, Tsft (u64 mactime)
	{1, 1}, // 1, Flags (u8 flags)
	{1, 1}, // 2, Rate (u8)
	{4, 2}, // 3, Channel (u16 frequency, u16 flags)
	{2, 2}, // 4, Fhss (u8 hop set, u8 hop pattern)
	{1, 1}, // 5, AntennaSignal (s8)
	{1, 1}, // 6, AntennaNoise (s8)
	{2, 2}, // 7, LockQuality (u16)
	{2, 2}, // 8, TxAttenuation (u16)
	{2, 2}, // 9, DbTxAttenuation (u16)
	{1, 1}, // 10, DbmTxPower (s8)
	{1, 1}, // 11, Antenna (u8)
	{1, 1}, // 12, DbAntennaSignal (u8)
	{1, 1}, // 13, DbAntennaNoise (u8)
	{2, 2}, // 14, RxFlags (u16)
	{2, 2}, // 15, TxFlags (u16 flags)
	{1, 1}, // 16, RtsRetries (u8 retries)
	{1, 1}, // 17, DataRetries (u8 retries)
	{4, 4}, // 18, XChannel (u32 flags, u16 freq, u8 channel, u8 maxpower)
	{3, 1}, // 19, Mcs (u8 known, u8 flags, u8 mcs)
	{8, 4}, // 20, AMpdu (u32 reference number, u16 flags, u8 delimiter CRC value, u8 reserved)
	{16, 2}, // 21, Vht (u16 known, u8 flags, u8 bandwidth, u8 mcs_nss[4], u8 coding, u8 group_id, u16 partial_aid)
	{12, 8}, // 22, Times (u64 timestamp, u16 accuracy, u8 unit/position, u8 flags)
	{12, 2}, // 23, He (u16 data1, data2, data3, data4, data5, data6)
	{12, 2}, // 24, HeMu (u16 flags1, u16 flags2, u8 RU_channel1[4], u8 RU_channel2[4])
	{6, 2}, // 25, HeMuOtherUser (u16 per_user_1, per_user_2, u8 per_user_position, per_user_known)
	{1, 1}, // 26, ZeroLenghPsdu (u8 type)
	{4, 2}, // 27, LSig (u16 data1, data2)
	{4, 4}, // 28, Tlv (list of TLVs detailed below)
	{0, 0}, // 29, RadiotapNamespace (no contents)
	{6, 2}, // 30, VendorNamespace (u8 OUI[3], u8 sub_namespace, u16 skip_length)
	{0, 0}, // 31, Ext
};

using namespace ieee80211_radiotap_field;
struct radio_tap_header_parsed{
    uint8_t        version;     /* set to 0 */
    uint8_t        pad;
    uint16_t       len;
    std::vector<uint32_t> present_flags;
    struct presence_value{
        enum ieee80211_radiotap_presence presence;
        std::variant<bool, Tsft, Flags, Rate, Channel, Fhss, AntennaSignal, AntennaNoise,
                 LockQuality, TxAttenuation, DbTxAttenuation, DbmTxPower, 
                 Antenna, DbAntennaSignal, DbAntennaNoise, RxFlags, TxFlags, 
                 RtsRetries, DataRetries, XChannel, Mcs, AMpdu, Vht, Times, He,
                 HeMu, HeMuOtherUser, ZeroLengthPsdu, LSig, Tlv,
                 RadiotapNamespace, VendorNamespace, Ext> value;
    };
    std::vector<std::vector<presence_value>> fields_of_present_flags;
    auto getValueOfField(int n_present_flags, enum ieee80211_radiotap_presence presence) {
        if (n_present_flags < fields_of_present_flags.size()) {
            for (const auto& field : fields_of_present_flags[n_present_flags]) {
                if (field.presence == presence)
                    return field.value;
            }
        }
        throw std::runtime_error("Presence not found");
    }
};

void printHexOfPacket(struct pcap_pkthdr* const packet_info, const unsigned char* packet);
/**
 * @brief 패킷된 pcap인덱스를 통해 파싱을 하고 파싱된 radio tap Header 정보를 반환
 * 
 * @param packet_info pcap패킷 정보
 * @param packet pcap인덱스; radio tap header를 가리키고 있어야함
 */
void parserRadioTapHeader(
        std::vector<radio_tap_header_parsed> &parsed_packets,
        struct pcap_pkthdr* const packet_info,
        const unsigned char **packet
        );
/**
 * @brief Present flags정보를 파싱해서 radio_tap_header_parsed구조체에 반영하는 함수
 * 
 * @param current_header radio_tap_header_parsed구조체
 * @param present_flags 분석 대상인 present_flags
 * @return true 다음 Present flags가 있다
 * @return false 다음 Present flags가 있다
 */
bool parserPresentFlags(struct radio_tap_header_parsed *current_header, uint32_t present_flags);

void parseAndAssignValueOfField(radio_tap_header_parsed::presence_value &field, const unsigned char *packet);