#include "pch.h"
#include "ux.h"
void printFirstDescribe(){
    std::cout<<"Hello! This is airodump clone coded program by liini."<<std::endl;
    std::cout<<"Below is your activated network interfaces. Please enter number that you want to sniff."<<std::endl;
    PRINT_HYPHEN_LINE();
}
std::string getInterfaceUserChoice(){
    pcap_if_t *all_interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::map<int, std::string> interfaces;

    if(pcap_findalldevs(&all_interfaces, errbuf) == -1)
        HANDLE_ERROR_RETURN_NULLPTR("pcap_findalldevs", errbuf);
    int i=1;
    for(pcap_if_t *iter = all_interfaces; iter != NULL; iter = iter->next){
        std::string interface = std::string(iter->name);
        std::cout<<i<<". "<<interface<<std::endl;
        interfaces.insert({i, interface});
        i++;
    }
    pcap_freealldevs(all_interfaces);

    size_t choice;
    do{
        std::cout<<"Enter>>";
        std::cin>>choice;
    }while(choice < 1 || choice > interfaces.size());
    
    return interfaces[choice];
}