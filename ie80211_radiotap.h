enum ieee80211_radiotap_presence {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	IEEE80211_RADIOTAP_XCHANNEL = 18,/* 18 is XChannel, but it's not defined yet */
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_TIMESTAMP = 22,
	IEEE80211_RADIOTAP_HE = 23,
	IEEE80211_RADIOTAP_HEMU = 24,
	IEEE80211_RADIOTAP_HEMUOTHERUSER = 25,
	IEEE80211_RADIOTAP_ZEROLENGTHPSDU = 26,
	IEEE80211_RADIOTAP_LSIG = 27,
	IEEE80211_RADIOTAP_TLV = 28,
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};

namespace ieee80211_radiotap_field {
	struct Tsft {
		uint64_t mactime;
	};

	struct Flags {
		uint8_t flags;
	};

	struct Rate {
		uint8_t rate;
	};

	struct Channel {
		uint16_t frequency;
		uint16_t flags;
	};

	struct Fhss {
		uint8_t hop_set;
		uint8_t hop_pattern;
	};

	struct AntennaSignal {
		int8_t signal;
	};

	struct AntennaNoise {
		int8_t noise;
	};

	struct LockQuality {
		uint16_t quality;
	};

	struct TxAttenuation {
		uint16_t attenuation;
	};

	struct DbTxAttenuation {
		uint16_t attenuation;
	};

	struct DbmTxPower {
		int8_t power;
	};

	struct Antenna {
		uint8_t antenna;
	};

	struct DbAntennaSignal {
		uint8_t signal;
	};

	struct DbAntennaNoise {
		uint8_t noise;
	};

	struct RxFlags {
		uint16_t flags;
	};

	struct TxFlags {
		uint16_t flags;
	};

	struct RtsRetries {
		uint8_t retries;
	};

	struct DataRetries {
		uint8_t retries;
	};

	struct XChannel {
		uint32_t flags;
		uint16_t freq;
		uint8_t channel;
		uint8_t maxpower;
	};

	struct Mcs {
		uint8_t known;
		uint8_t flags;
		uint8_t mcs;
	};

	struct AMpdu {
		uint32_t reference_number;
		uint16_t flags;
		uint8_t delimiter_CRC_value;
		uint8_t reserved;
	};

	struct Vht {
		uint16_t known;
		uint8_t flags;
		uint8_t bandwidth;
		uint8_t mcs_nss[4];
		uint8_t coding;
		uint8_t group_id;
		uint16_t partial_aid;
	};

	struct Times {
		uint64_t timestamp;
		uint16_t accuracy;
		uint8_t unit_position;
		uint8_t flags;
	};

	struct He {
		uint16_t data1;
		uint16_t data2;
		uint16_t data3;
		uint16_t data4;
		uint16_t data5;
		uint16_t data6;
	};

	struct HeMu {
		uint16_t flags1;
		uint16_t flags2;
		uint8_t RU_channel1[4];
		uint8_t RU_channel2[4];
	};

	struct HeMuOtherUser {
		uint16_t per_user_1;
		uint16_t per_user_2;
		uint8_t per_user_position;
		uint8_t per_user_known;
	};

	struct ZeroLengthPsdu {
		uint8_t type;
	};

	struct LSig {
		uint16_t data1;
		uint16_t data2;
	};

	struct Tlv {
		//애매모호해서 U<size>로 해석함
		uint32_t data;
	};

	struct RadiotapNamespace {
		//사용되지않음
	};

	struct VendorNamespace {
		uint8_t OUI[3];
		uint8_t sub_namespace;
		uint16_t skip_length;
	};

	struct Ext {
		// 내용이 없다고 주어져 있어서, 일단 빈 구조체로 둡니다.
	};
}

inline uint32_t getMaskRadiotapPresence(enum ieee80211_radiotap_presence presence){
	return 1<<presence;
}
inline uint32_t getMaskRadiotapPresence(int number_ieee80211_radiotap_presence){
	return 1<<number_ieee80211_radiotap_presence;
}