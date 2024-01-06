#pragma once
#include <string>
#include <map>
#include <sys/ioctl.h>
#include <unistd.h>
#define PRINT_HYPHEN_LINE() do { \
    struct winsize w; \
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w); \
    for(int i = 0; i < w.ws_col; ++i) \
        std::cout << '-'; \
    std::cout << '\n'; \
} while (0)
#define CLEAR_SCREEN() do { \
    std::cout << "\x1B[2J\x1B[H"; \
} while(0)
#define USE_ALTERNATE_BUFFER() do { \
    std::cout << "\x1B[?1049h"; \
} while(0)
#define USE_NORMAL_BUFFER() do { \
    std::cout << "\x1B[?1049l"; \
} while(0)
void printFirstDescribe();
std::string getInterfaceUserChoice();