#include "pch.h"
#include "ie80211_radiotap.h"

#ifdef UNIT_TEST
#include <gtest/gtest.h>

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif