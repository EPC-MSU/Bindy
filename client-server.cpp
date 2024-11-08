#include "bindy-static.h"


void fail (const char* message) {
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
		bindy_ptr = new bindy::Bindy(argv[1], false, false);
	} catch (...) {
		fail("Error initializing bindy. Please check if configuration file exists.");
	}

	std::cout << "CLIENT started.\n";
	bindy::conn_id_t conn_id;
	try {
		conn_id = bindy_ptr->connect(argv[2]);
	} catch (...) {
		fail("Error establishing connection to remote address.");
	}

	try {
		// Send user message
		std::vector<uint8_t> data = std::vector<uint8_t>(argv[3], argv[3] + strlen(argv[3]));
		bindy_ptr->send_data(conn_id, data);
		bindy::sleep_ms(1000); // let the server process the data
	} catch (...) {
		fail("Error sending data.");
	}
}


void run_server(char *argv[]) {
	bindy::Bindy *bindy_ptr;
	try {
		bindy_ptr = new bindy::Bindy(argv[1], true, true);
	} catch (...) {
		fail("Error initializing bindy. Please check if configuration file exists.");
	}

	try {
		bindy_ptr->connect();
		bindy_ptr->set_handler(&handler_function);
	} catch (...) {
		fail("Error establishing listening connection.");
	}
	std::cout << "SERVER started.\n";

	while (true) {
		std::list<bindy::conn_id_t> connections = bindy_ptr->list_connections();
		const int buffer_size = 1024;
		uint8_t buffer[buffer_size + 1];
		for (std::list<bindy::conn_id_t>::iterator it = connections.begin(); it != connections.end(); ++it) {
			int read_data_size = bindy_ptr->read(*it, buffer, buffer_size);
			if (read_data_size > 0) {
				buffer[read_data_size] = 0;
				struct in_addr client_address = bindy_ptr->get_ip(*it);
				std::cout << "Client from host " << inet_ntoa(client_address) << " says: " << (const char*)buffer << std::endl;
				std::cout.flush();
			}
		}
		bindy::sleep_ms(10);
	}
}


int main (int argc, char *argv[])
{
    bindy::BindyNetworkInitializer initializer;

	if (argc == 4) { // I am a Client
		run_client(argv);
	} else if (argc == 2) { // I am a Server
		run_server(argv);
	} else { // I don't even
		std::cout << "Call '" << argv[0] << " KEYFILE IP TEXT' to become a client node and send a message \"TEXT\" to node with \"IP\" address." << std::endl;
		std::cout << "Call '" << argv[0] << " KEYFILE' to become a server node and listen to/receive messages from client and server nodes." << std::endl;
		std::cout << "KEYFILE is a file containing authorization data. Server node must be able to find a key of client node in its keyfile." << std::endl;
	}

	return 0;
}
