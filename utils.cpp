#include <iostream>
#include "utils.h"


namespace bindy {

void parse_host_and_port(std::string *address, std::string *host, int *port) {
    size_t colon_position = address->find_last_of(":");
    
    try {
        *port = parse_port(address, colon_position);
        host->assign(*address, 0, colon_position);
    }
    catch (std::invalid_argument &exc) {
        *port = -1;
        host->assign(*address);
        std::cerr << exc.what() << "\n";
    }
}


int parse_port(std::string* address, size_t colon_position) {
    size_t port_string_size = address->size() - colon_position - 1;
    std::string port_string = address->substr(colon_position + 1, port_string_size);
    size_t pos;
    int port = std::stoi(port_string, &pos);
    if (pos != port_string_size) {
        throw std::invalid_argument("Failed to parse port correctly");
    }
    return port;
}

}
