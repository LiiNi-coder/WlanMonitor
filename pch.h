#pragma once
#include <iostream>
#include <string>
#include <thread>
#include <queue>
#include <mutex>

#include <pcap.h>

#define DEBUG_VAR(var) if (debug_mode) std::cout << #var << ": " << var << std::endl;
#define HANDLE_ERROR(func_name, errbuf) \
    do { \
        fprintf(stderr, "Error in %s: %s\n", func_name, errbuf); \
        return nullptr; \
    } while (0)