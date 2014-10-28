#include "bindy.h"

void handler_function(conn_id_t conn_id, std::vector<uint8_t> data) {
	std::string text = std::string(data.begin(), data.end());
	std::cout << text << std::endl;
	std::cout.flush();
}

void fail (const char* message) {
	std::cout << message << std::endl;
	exit(1);
}

int main (int argc, char *argv[]) {
	#if defined(WIN32) || defined (WIN64)
	CryptoPP::Socket::StartSockets();
	#endif

	Bindy * bindy = NULL;
	if (argc == 4) { // I am a Client
		try {
			bindy = new Bindy(argv[1], false, false);
		} catch (...) {
			fail("Error initializing Bindy. Please check if configuration file exists.");
		}
		std::cout << "CLIENT started." << std::endl;
		conn_id_t conn_id;
		try {
			conn_id = bindy->connect(argv[2]);
		} catch (...) {
			fail("Error establishing connection to remote address.");
		}
		try {
			std::string text = std::string(argv[3]);
			std::vector<uint8_t> data = std::vector<uint8_t>(text.begin(), text.end());
			bindy->send_data(conn_id, data);
			sleep(1000); // let the server process the data
		} catch (...) {
			fail("Error sending data.");
		}
	} else if (argc == 2) { // I am a Server
		try {
			bindy = new Bindy(argv[1], true, true);
		} catch (...) {
			fail("Error initializing Bindy. Please check if configuration file exists.");
		}
		try {
			bindy->connect();
			bindy->set_handler(&handler_function);
		} catch (...) {
			fail("Error establishing listening connection.");
		}
		std::cout << "SERVER started." << std::endl;

		while (true) {
			std::list<conn_id_t> c = bindy->list_connections();
			std::list<conn_id_t>::iterator it;
			const int buflen = 1024;
			byte buf[buflen+1];
			int len;
			for (it = c.begin(); it != c.end(); ++it) {
				len = bindy->read(*it, buf, buflen);
				if (len > 0) {
					buf[len] = 0;
					std::string str((const char*)buf);
					std::cout << str << std::endl;
					std::cout.flush();
				}
			}
			sleep(10);
		}
	} else { // I don't even
		std::cout << "Call '" << argv[0] << " KEYFILE IP TEXT' to become a client node and send a message \"TEXT\" to node with \"IP\" address." << std::endl;
		std::cout << "Call '" << argv[0] << " KEYFILE' to become a server node and listen to/receive messages from client and server nodes." << std::endl;
		std::cout << "KEYFILE is a file containing authorization data. Server node must be able to find a key of client node in its keyfile." << std::endl;
	}
	delete bindy;

	#if defined(WIN32) || defined (WIN64)
	CryptoPP::Socket::ShutdownSockets();
	#endif

	return 0;
}