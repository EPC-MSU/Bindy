#ifndef	BINDY_H
#define BINDY_H

#include <memory>
#include <vector>
#include <list>
#include <string>
#include <iostream>

#if defined (WIN32) || defined(WIN64)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

// MSVC symbols export
#if defined (WIN32) || defined(WIN64)
  #if defined(bindy_EXPORTS)
    #define BINDY_EXPORT __declspec(dllexport)
  #else
    #define BINDY_EXPORT __declspec(dllimport)
  #endif
#else
 #define BINDY_EXPORT
#endif


namespace bindy
{

// aes-128
const size_t AES_KEY_LENGTH = 16;
typedef struct BINDY_EXPORT {
	uint8_t bytes[AES_KEY_LENGTH];
} aes_key_t;

const size_t USERNAME_LENGTH = 32;
typedef struct BINDY_EXPORT {
	char username[USERNAME_LENGTH];
	aes_key_t key;
} login_pair_t;

namespace link_pkt {
	enum {
		PacketData = 0,
		PacketInitRequest = 1,
		PacketInitReply = 2,
		PacketLinkInfo = 3,
		PacketTermRequest = 254,
		PacketTermReply = 255
	};
}

typedef struct BINDY_EXPORT {
	uint32_t packet_length;
	uint8_t  packet_type;
	uint8_t  reserved1;
	uint8_t  reserved2;
	uint8_t  reserved3;
} header_t;

typedef uint32_t conn_id_t;

class BINDY_EXPORT Message {
public:
	Message(size_t packet_length, uint8_t packet_type);
	Message(header_t header);
	Message(const Message& other);
	~Message();
//private:
	header_t header;
	uint8_t * p_body;
};

typedef std::vector<login_pair_t> login_vector_t;

void BINDY_EXPORT sleep_ms(size_t ms);

class BINDY_EXPORT Connection;
class BINDY_EXPORT BindyState;

class BINDY_EXPORT Bindy {
public:
	Bindy(std::string filename, bool is_active_node, bool is_buffered);
	~Bindy();

	void set_handler (void (* datasink)(conn_id_t conn_id, std::vector<uint8_t> data));
	void set_discnotify (void (* discnotify)(conn_id_t conn_id));
	 // Server method, starts listening on a socket in background and returns
	void connect ();
	// Client method; each connect(addr) opens new socket to the "addr" and
	// establishes its own encrypted channel
	conn_id_t connect (char * addr);
	 // Diconnect does not affect other connections to the same ip
	void disconnect(conn_id_t conn_id);
	void send_data (conn_id_t conn_id, std::vector<uint8_t> data);
	void get_master_key(uint8_t* ptr);
	std::string get_master_name();
	bool get_is_server();
	void callback_data (conn_id_t conn_id, std::vector<uint8_t> data);
	void callback_disc (conn_id_t conn_id);
	std::list<conn_id_t> list_connections ();
	// Try to read "size" bytes from buffer into "p"
	// Returns amount of bytes read and removed from buffer
	int read (conn_id_t conn_id, uint8_t * p, int size);
	// returns amount of data in buffer
	int get_data_size (conn_id_t);

	// + Getters-setters for parameterss
	void set_nodename (std::string nodename);
	std::string get_nodename (void);
	void add_connection(conn_id_t conn_id, Connection * conn);
	void delete_connection(conn_id_t conn_id);
	in_addr get_ip(conn_id_t conn_id);

	static void initialize_network();
	static void shutdown_network();

	const int port_;
	bool is_server;
	bool is_buffered;
	// ...
	void merge_cloud_info (login_vector_t login_vector);
	void change_master_key (login_pair_t login_pair);

private:
	BindyState* bindy_state_;

	friend void socket_thread_function(void* arg);
	friend void main_thread_function(void* arg);

	Bindy(const Bindy&) = delete;
	Bindy& operator=(const Bindy&) = delete;
};


class BindyNetworkInitializer
{
	BindyNetworkInitializer(const BindyNetworkInitializer&);
	BindyNetworkInitializer& operator=(const BindyNetworkInitializer&);
public:
	BindyNetworkInitializer()  { Bindy::initialize_network(); }
	~BindyNetworkInitializer() { Bindy::shutdown_network(); }
};

};

#endif // BINDY_H
