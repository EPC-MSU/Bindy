#include "bindy-static.h"


void fail(const char *message) {
    std::cout << message << std::endl;
    exit(1);
}


void handler_function(bindy::conn_id_t, std::vector<uint8_t> data) {
    std::string text(data.begin(), data.end());
    std::cout << text << std::endl;
    std::cout.flush();
}


void run_client(char *argv[]) {
    bindy::Bindy *bindy_ptr;

    try {
        bindy_ptr = bindy::bindy_create_new(argv[1], false, false);
    } catch (...) {
        fail("Error initializing bindy. Please check if configuration file exists.");
    }

    std::cout << "CLIENT started.\n";
    bindy::conn_id_t conn_id;
    try {
        conn_id = bindy::bindy_connect_client(bindy_ptr, argv[2]);
    } catch (...) {
        fail("Error establishing connection to remote address.");
    }

    try {
        // Send user message
        bindy::bindy_send_data(bindy_ptr, conn_id, (uint8_t *)argv[3], strlen(argv[3]));
        bindy::sleep_ms(1000); // let the server process the data
    } catch (...) {
        fail("Error sending data.");
    }
}


void run_server(char *argv[]) {
    bindy::Bindy *bindy_ptr;

    try {
        bindy_ptr = bindy::bindy_create_new(argv[1], true, true);
    } catch (...) {
        fail("Error initializing bindy. Please check if configuration file exists.");
    }

    try {
        bindy::bindy_connect_server(bindy_ptr);
        bindy_ptr->set_handler(&handler_function);
    } catch (...) {
        fail("Error establishing listening connection.");
    }
    std::cout << "SERVER started.\n";

    while (true) {
        bindy::conn_id_t *connections = nullptr;
        size_t connections_number = bindy::bindy_list_connections(bindy_ptr, &connections);

        const int buffer_size = 1024;
        uint8_t buffer[buffer_size + 1];
        for (int i = 0; i < connections_number; i++) {
            bindy::conn_id_t conn_id = connections[i];
            int len = bindy::bindy_read_data(bindy_ptr, conn_id, buffer, buffer_size);
            if (len > 0) {
                buffer[len] = 0;
                std::cout << "Client from host " << bindy::bindy_get_ip_address(bindy_ptr, conn_id) << " says: " << (const char *)buffer << std::endl;
                std::cout.flush();
            }
        }

        if (connections) {
            delete[] connections;
            connections = nullptr;
        }

        bindy::sleep_ms(10);
    }
}


int main(int argc, char *argv[]) {
    bindy::bindy_initialize_network();

    if (argc == 4) {
        run_client(argv);
    } else if (argc == 2) {
        run_server(argv);
    } else {
        std::cout << "Call '" << argv[0] << " KEYFILE IP TEXT' to become a client node and send a message \"TEXT\" to node with \"IP\" address." << std::endl;
        std::cout << "Call '" << argv[0] << " KEYFILE' to become a server node and listen to/receive messages from client and server nodes." << std::endl;
        std::cout << "KEYFILE is a file containing authorization data. Server node must be able to find a key of client node in its keyfile." << std::endl;
    }

    bindy::bindy_shutdown_network();
    return 0;
}
