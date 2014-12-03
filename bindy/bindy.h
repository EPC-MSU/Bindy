#ifndef	BINDY_H
#define BINDY_H

	// $Id$
	/**
	 * @file bindy.h
	 * Write description of source file here for dOxygen.
	 *
	 * @brief Can use "brief" tag to explicitly generate comments for file documentation.
	 *
	 */
	// $Log$
	  

	/**
	Write description of function here.
	The function should follow these comments.
	Use of "brief" tag is optional. (no point to it)

	The function arguments listed with "param" will be compared
	to the declaration and verified.

	@param[in]     _inArg1 Description of first function argument.
	@param[out]    _outArg2 Description of second function argument.
	@param[in,out] _inoutArg3 Description of third function argument.
	@return Description of returned value.
	*/

// To use the DLL version of Crypto++, this file must be included before any other Crypto++ header files.
//#include "dll.h"

#include <array>
#include <vector>

#include <iostream>     // std::cout
#include <fstream>      // std::ifstream



#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "aes.h"
using CryptoPP::AES;

#include "gcm.h"
using CryptoPP::GCM;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "socketft.h"
using CryptoPP::Socket;
// === crypto ends here

#include "tinythread.h"

//#include "sqlite3.h"

#include <list>
#include "circular_buffer.h"

#if defined (WIN32) || defined(WIN64)
//
#else
#include <sys/types.h> 
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

// common sleep function (conditional define (urgh))
#if defined(WIN32) || defined(WIN64)
	#define sleep(ms)	Sleep(ms)
#else
	#define sleep(ms)	usleep(1000 * ms)
#endif


typedef unsigned char uint8_t;
typedef unsigned int uint32_t; // strictly speaking this is not true...

#include "aes.h"

typedef struct {
#if defined (WIN32) || defined(WIN64)
	std::tr1::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH> bytes;
#else
	std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH> bytes;
#endif
} aes_key_t;

const int USERNAME_LENGTH = 32;
typedef struct {
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

const int PORT = 12345;

typedef struct {
	uint32_t packet_length;
	uint8_t packet_type;
	uint8_t reserved1;
	uint8_t reserved2;
	uint8_t reserved3;
} header_t;

typedef uint32_t conn_id_t;

class Message {
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


class Connection {
public:
	Connection();
	Connection(const Connection& other);
	~Connection();
//private:
	Socket * sock;
	SecByteBlock * send_key;
	SecByteBlock * recv_key;
	SecByteBlock * send_iv;
	SecByteBlock * recv_iv;
	tthread::mutex * send_mutex;
	tthread::mutex * recv_mutex;
	/*spm::circular_buffer<byte>*/ std::deque<uint8_t> * buffer;
};

class Bindy {
public:
	Bindy(std::string filename, bool is_active_node, bool is_buffered);
	~Bindy();

	void set_handler (void (* datasink)(conn_id_t conn_id, std::vector<uint8_t> data));
	void set_discnotify (void (* discnotify)(conn_id_t conn_id));
	void connect (); // server method, starts listening on a socket in background and returns
	conn_id_t connect (char * addr); // client method; each connect(addr) opens new socket to the "addr" and establishes its own encrypted channel
	void disconnect(conn_id_t conn_id); // disconnect does not affect other connections to the same ip
	void send_data (conn_id_t conn_id, std::vector<uint8_t> data);
	void get_master_key(byte* ptr);
	std::string get_master_name();
	bool get_is_server() { return is_server; }
	void callback_data (conn_id_t conn_id, std::vector<uint8_t> data);
	void callback_disc (conn_id_t conn_id);
	std::list<conn_id_t> list_connections ();
	int read (conn_id_t conn_id, byte * p, int size); // tries to read "size" bytes from buffer into "p"; returns amount of bytes read and removed from buffer
	int get_data_size (conn_id_t); // returns amount of data in buffer
	// + Getters-setters for params below
	void set_nodename (std::string nodename) { this->nodename = nodename; }
	std::string get_nodename (void) { return this->nodename; }
	void add_connection(conn_id_t conn_id, Connection * conn);
	void delete_connection(conn_id_t conn_id);
	void assign_key_by_name(std::string name, SecByteBlock *key);

protected:
	uint32_t max_live_tunnels;
	bool is_server;
	bool is_buffered;
	// ...
	void merge_cloud_info (login_vector_t login_vector);
	void change_master_key (login_pair_t login_pair);

private:
	void (* m_datasink)(conn_id_t conn_id, std::vector<uint8_t> data);
	void (* m_discnotify)(conn_id_t conn_id);
	std::map<std::string, aes_key_t> login_key_map;
	tthread::thread * main_thread;
	std::map<conn_id_t, Connection*> connections;
	tthread::mutex mutex; // global mutex
	std::string nodename; // name of this node
	login_pair_t master_login; // root key
};

typedef struct {
	Bindy * class_ptr;
	Socket * sock_ptr;
	bool inits_connect;
	bool connect_ok;
	conn_id_t conn_id;
	bool is_buffered;
} thread_param_t;

std::string hex_encode(const char* s, unsigned int size);
std::string hex_encode(std::string s);
std::string hex_encode(std::vector<uint8_t> v);

#endif // BINDY_H
