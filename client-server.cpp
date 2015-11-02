#include "bindy.h"

void handler_function(bindy::conn_id_t conn_id, std::vector<uint8_t> data) {
	std::string text(data.begin(), data.end());
	std::cout << text << std::endl;
	std::cout.flush();
}

void fail (const char* message) {
	std::cout << message << std::endl;
	exit(1);
}

int main (int argc, char *argv[])
{
	bindy::BindyNetworkInitializer initializer;

	std::unique_ptr<bindy::Bindy> bindy;
	if (argc == 4) { // I am a Client
		try {
			bindy.reset(new bindy::Bindy(argv[1], false, false));
		} catch (...) {
			fail("Error initializing Bindy. Please check if configuration file exists.");
		}
		std::cout << "CLIENT started." << std::endl;
		bindy::conn_id_t conn_id;
		try {
			conn_id = bindy->connect(argv[2]);
		} catch (...) {
			fail("Error establishing connection to remote address.");
		}
		try {
			auto result = bindy->list_users_local();

			std::string text = std::string(argv[3]);
			std::vector<uint8_t> data = std::vector<uint8_t>(text.begin(), text.end());
//			bindy->send_data(conn_id, data);
			auto uuid_future = bindy->add_user_remote(conn_id, {"qqqqaaaabbbbccccqqqqaaaabbbbcccc", }, bindy::aes_key_t{"5aqq4qqqqqqqqq\0"});
			uuid_future.wait();
			auto uuid = uuid_future.get();
			std::cout << uuid;
			bindy->set_master_remote(conn_id, uuid).wait();

//			bindy->change_key_remote(conn_id, uuid, bindy::aes_key_t{"xxxxxxxxxxxxxx\0"}).wait();
//			bindy->del_user_remote(conn_id, uuid	).wait();
			bindy::sleep_ms(1000); // let the server process the data
		} catch (...) {
			fail("Error sending data.");
		}
	} else if (argc == 2) { // I am a Server
		try {
			bindy.reset(new bindy::Bindy(argv[1], true, true));
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
			std::list<bindy::conn_id_t> c = bindy->list_connections();
			std::list<bindy::conn_id_t>::iterator it;
			const int buflen = 1024;
			uint8_t buf[buflen+1];
			char addrbuf[INET_ADDRSTRLEN];
			int len;
			for (it = c.begin(); it != c.end(); ++it) {
				len = bindy->read(*it, buf, buflen);
				if (len > 0) {
					buf[len] = 0;
					struct in_addr client_addr = bindy->get_ip(*it);
					std::cout << "Client from host "
						<< inet_ntoa(client_addr)
						<< " says: " << (const char*)buf << std::endl;
					std::cout.flush();
				}
			}
			bindy::sleep_ms(10);
		}
	} else { // I don't even
		std::cout << "Call '" << argv[0] << " KEYFILE IP TEXT' to become a client node and send a message \"TEXT\" to node with \"IP\" address." << std::endl;
		std::cout << "Call '" << argv[0] << " KEYFILE' to become a server node and listen to/receive messages from client and server nodes." << std::endl;
		std::cout << "KEYFILE is a file containing authorization data. Server node must be able to find a key of client node in its keyfile." << std::endl;
	}

	return 0;
}
