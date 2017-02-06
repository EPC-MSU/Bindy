/// @file
/// @mainpage Bindy API Reference
///
/// @section intro_sec Introduction
/// Bindy synopsis
///


#include "bindy-static.h"

#include <fstream>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <cassert>

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/gcm.h>
#include <cryptopp/socketft.h>

#include "tinythread.h"
#include "sqlite/sqlite3.h"
#include "sole/sole.hpp"


using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::ArraySink;
using CryptoPP::AES;
using CryptoPP::Socket;

#undef min
#undef max

// conditional includes for different platforms
#if defined(WIN32) || defined(WIN64)
#include <mstcpip.h>
#endif

// ------------------------------------------------------------------------------------
// Implementation


namespace bindy {
static tthread::mutex *stdout_mutex = new tthread::mutex();

//#define DEBUG_ENABLE
#define DEBUG_PREFIX ""
#ifdef DEBUG_ENABLE
#define DEBUG(text) { stdout_mutex->lock(); std::cout << DEBUG_PREFIX << text << std::endl; stdout_mutex->unlock(); }
#else
#define DEBUG(text) { ; }
#endif

/*! TCP KeepAlive option: Keepalive probe send interval in seconds. */
#define KEEPINTVL 5

/*! TCP KeepAlive option: Socket idle time before keepalive probes are sent, in seconds. */
#define KEEPIDLE 10

/*! TCP KeepAlive option: Keepalive probe count. */
#define KEEPCNT 3

/// Crossplatform sleep
void sleep_ms(size_t ms) {
#if defined(WIN32) || defined(WIN64)
	Sleep((DWORD)ms);
#else
	usleep(1000 * ms);
#endif
}

/*! Acknowledgement identifier */
typedef sole::uuid ack_id_t;

/*!
* Header type for the Message class. Contains information about message contents.
*/
typedef struct {
	/*! Packet length in bytes, excluding the header size. */
	uint32_t data_length;

	/*! Packet type. */
	link_pkt packet_type;

	/*! Reserved for future use. */
	uint8_t  reserved1;

	/*! Reserved for future use. */
	uint8_t  reserved2;

	/*! Reserved for future use. */
	uint8_t  reserved3;
} header_t;

/*! A helper type which contains a single message(type+content) to be encrypted and sent over the TCP socket. */
struct Message {
	link_pkt type;
	std::vector<uint8_t> content;
};

/*! Acknowldegement callback */
typedef std::function<void(const std::vector<uint8_t>)> ack_callback_t;

/*! Lock guard short type definition. */
typedef tthread::lock_guard<tthread::mutex> tlock;

/* Broadcast data struct definition */
typedef struct bcast_data_t {
	std::vector<uint8_t> data;
	std::string addr;
} bcast_data_t;

/*! This function takes a pointer to an array of chars and its size and returns its representation in hex as a string. */
std::string hex_encode(const char *s, size_t size) {
	std::string encoded;
	StringSource(reinterpret_cast<const uint8_t *>(s), size, true,
				 new CryptoPP::HexEncoder(
					 new StringSink(encoded), true, 2, " "
				 ) // HexEncoder
	); // StringSource
	return encoded;
}

std::string hex_encode(std::string s) {
	return hex_encode(s.c_str(), s.size());
}

std::string hex_encode(std::vector<uint8_t> v) {
	return hex_encode((const char *) &v[0], v.size());
}

/*! Helper function for CryptoPP encode/decode functions which require an std::string as parameter. Copies characters into the string. */
void string_set(std::string *str, char *buf, int size) {
	str->resize(size);
	for(int i = 0; i < size; i++) {
		str->at(i) = buf[i];
	}
}

void string_set(std::string *str, uint8_t *buf, int size) {
	string_set(str, reinterpret_cast<char *>(buf), size);
}

class BindyState {
public:
	void (*m_datasink)(conn_id_t conn_id, std::vector<uint8_t> data);

	void (*m_discnotify)(conn_id_t conn_id);

//	std::map<std::string, aes_key_t> login_key_map;
	tthread::thread *main_thread;
	tthread::thread *bcast_thread;
	std::map<conn_id_t, SuperConnection *> connections;
	tthread::mutex mutex; // global mutex
	tthread::mutex interlock_mutex; // mutex to sync betweern listening TCP and UDP threads
	std::string nodename; // name of this node
//	user_t master; // root key
	sqlite3 *sql_conn;

	BindyState() {
	}

	~BindyState() {
	}

private:
	BindyState(const BindyState &) = delete;

	BindyState &operator=(const BindyState &) = delete;
};

class Countable {
public:
	Countable(conn_id_t id) {
		tlock lock(global_mutex);
		this->conn_id = id;
		if(map.count(conn_id) == 0) {
			map[conn_id] = 0;
		}
		map_prev[conn_id] = map[conn_id];
		++map[conn_id];
		mutexes[conn_id] = new tthread::mutex();
	}

	Countable(Countable const &) = delete;

	Countable &operator=(Countable const &) = delete;

	virtual ~Countable() {
		tlock lock(global_mutex);
		if(map.count(conn_id) == 1 && map[conn_id] > 1) {
			map_prev[conn_id] = map[conn_id];
			--map[conn_id];
		} else {
			map.erase(conn_id);
			map_prev.erase(conn_id);
			delete mutexes[conn_id];
			mutexes.erase(conn_id);
		}
	}

	unsigned int count() {
		tlock lock(global_mutex);
		return map[conn_id];
	}

	unsigned int count_prev() {
		tlock lock(global_mutex);
		return map_prev[conn_id];
	}

	tthread::mutex *mutex() {
		return mutexes[conn_id];
	}

private:
	conn_id_t conn_id;
	static std::map<conn_id_t, unsigned int> map;
	static std::map<conn_id_t, unsigned int> map_prev;
	static std::map<conn_id_t, tthread::mutex *> mutexes;
	static tthread::mutex global_mutex;
};

std::map<conn_id_t, unsigned int> Countable::map;
std::map<conn_id_t, unsigned int> Countable::map_prev;
std::map<conn_id_t, tthread::mutex *> Countable::mutexes;
tthread::mutex Countable::global_mutex;

int listen_conn_id = conn_id_invalid; // used in tcp- and udp-listen thread functions

bool set_socket_broadcast(Socket *s) {
	bool ok = true;
#ifdef __linux__
	int optval = 1;
	ok = (0 == setsockopt(*s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)));
#endif
	return ok;
}

bool set_socket_reuseaddr(Socket *s) {
	bool ok = true;
#ifdef __linux__
	int optval = 1;
	ok = (0 == setsockopt(*s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)));
#endif
	return ok;
}

/*!
* Class which contains information about a single connection.
*/
class Connection : public Countable {
public:
	Connection(Bindy *bindy, Socket *_socket, conn_id_t conn_id, bool inits);

	~Connection();

	Connection(Connection *other);

	/*!
	* Initializes shared socket.
	*/
	void init();

	/*!
	* Encrypts and sends a single message into this connection.
	*/
	void send_packet(const link_pkt type, const std::vector<uint8_t> content);

	/*!
	* Encrypts and sends a single message into this connection, then waits for acknowledgement message.
	*/
	void send_packet_ack(const link_pkt type, std::vector<uint8_t> &content, ack_callback_t &success, ack_callback_t &failure);

	/*!
	* Decrypts and returns a single packet read from the socket of this connection.
	*/
	Message recv_packet();

	/*!
	* Returns buffer size of this connection.
	*/
	unsigned int buffer_size();

	/*!
	* Reads up to "size" bytes of data from this connection buffer and puts them to the memory pointed to by "p". Returns amount of bytes read.
	*/
	int buffer_read(uint8_t *p, int size);

	/*!
	* Writes data into the buffer of this connection to be sent to the other party.
	*/
	void buffer_write(std::vector<uint8_t> data);

	/*!
	* Sends callback data from thread to the Bindy class through the Connection class intermediary.
	*/
	void callback_data(std::vector<uint8_t> data);

	/*!
	* Helper method to establish connection.
	*/
	void initial_exchange(bcast_data_t bcast_data);

private:
	Connection(const Connection &other);

	Connection &operator=(const Connection &other);

	Bindy *bindy;
	Socket *sock;
	CryptoPP::SecByteBlock *send_key;
	CryptoPP::SecByteBlock *recv_key;
	CryptoPP::SecByteBlock *send_iv;
	CryptoPP::SecByteBlock *recv_iv;
	tthread::mutex *send_mutex;
	tthread::mutex *recv_mutex;
	tthread::mutex *ack_mutex;
	std::deque<uint8_t> *buffer;
	conn_id_t conn_id;
	bool inits_connect;
	std::map<ack_id_t, std::pair<ack_callback_t, ack_callback_t>> *ack_callbacks;

	void disconnect_self();

	in_addr get_ip();

	friend class Bindy;

	friend void socket_thread_function(void *arg);
};

void socket_thread_function(void *arg);

class SuperConnection : public Connection {
public:
	SuperConnection(Bindy *bindy, Socket *_socket, conn_id_t conn_id, bool inits, bcast_data_t bcast_data);

	~SuperConnection();
};

SuperConnection::SuperConnection(Bindy *_bindy, Socket *_socket, conn_id_t conn_id, bool _inits_connect,
								 bcast_data_t bcast_data)
	:
	Connection(_bindy, _socket, conn_id, _inits_connect) {
	initial_exchange(bcast_data);
	tthread::thread *t = new tthread::thread(socket_thread_function, this);
	t->detach();
}

SuperConnection::~SuperConnection() {
}

Connection::Connection(Bindy *_bindy, Socket *_socket, conn_id_t conn_id, bool _inits_connect) :
	Countable(conn_id) {
	if(count() == 1) {
		this->inits_connect = _inits_connect;
		this->bindy = _bindy;
		this->sock = _socket;
		this->conn_id = conn_id;
		this->send_key = new CryptoPP::SecByteBlock(AES::DEFAULT_KEYLENGTH);
		this->recv_key = new CryptoPP::SecByteBlock(AES::DEFAULT_KEYLENGTH);
		this->send_iv = new CryptoPP::SecByteBlock(AES::BLOCKSIZE);
		this->recv_iv = new CryptoPP::SecByteBlock(AES::BLOCKSIZE);
		this->send_mutex = new tthread::mutex();
		this->recv_mutex = new tthread::mutex();
		this->ack_mutex = new tthread::mutex();
		this->buffer = new std::deque<uint8_t>();
		this->ack_callbacks = new std::map<ack_id_t, std::pair<ack_callback_t, ack_callback_t>>();
	}
}

Connection::Connection(Connection *other) :
	Countable(other->conn_id) {
	if(count() > 1) {
		this->inits_connect = other->inits_connect;
		this->bindy = other->bindy;
		this->sock = other->sock;
		this->conn_id = other->conn_id;
		this->send_key = other->send_key;
		this->recv_key = other->recv_key;
		this->send_iv = other->send_iv;
		this->recv_iv = other->recv_iv;
		this->send_mutex = other->send_mutex;
		this->recv_mutex = other->recv_mutex;
		this->ack_mutex = other->ack_mutex;
		this->buffer = other->buffer;
		this->ack_callbacks = other->ack_callbacks;
	}
}

Connection::~Connection() {
	tlock lock(*mutex());
	if(count() == 2) {
		int how;
#ifdef _MSC_VER
		how = SD_BOTH;
#else
		how = SHUT_RDWR;
#endif
		if(sock) {
			try {
				sock->ShutDown(how);
			}
			catch(CryptoPP::Socket::Err &e) {
				DEBUG("Socket shutdown failed for reason " << e.what() <<
					  ". Likely the other side closed connection first.");
			}
		}
	}
	else if(count() == 1) {
		if(sock) {
			sock->CloseSocket();
			delete sock;
		}
		delete buffer;

		delete send_key;
		delete recv_key;
		delete send_iv;
		delete recv_iv;
		delete send_mutex;
		delete recv_mutex;
		delete ack_mutex;
		delete ack_callbacks;
	}
}

void Connection::send_packet_ack(const link_pkt type, std::vector<uint8_t> &content, ack_callback_t &success, ack_callback_t &failure) {
	ack_id_t request_id = sole::uuid1();

	unsigned long orig_size = content.size();
	content.resize(content.size() + sizeof(ack_id_t));
	std::memcpy(content.data() + orig_size, &request_id, sizeof(ack_id_t));

	ack_mutex->lock();
	(*ack_callbacks)[request_id] = {std::move(success), std::move(failure)};
	ack_mutex->unlock();

	send_packet(type, content);
}

// Sends "message" data into the connection. Modifies connection IV in preparation for the next packet.
void Connection::send_packet(link_pkt type, const std::vector<uint8_t> content) {

	tlock lock(*send_mutex);

	header_t header{static_cast<uint32_t>(content.size()), type};
	std::string cipher_header, cipher_body, cipher_all,
		plain_header(reinterpret_cast<const char *>(&header), sizeof(header));

	CryptoPP::GCM<AES>::Encryption e;
	try {
		e.SetKeyWithIV(*send_key, send_key->size(), *send_iv, send_iv->size());
		StringSource(plain_header, true,
					 new CryptoPP::AuthenticatedEncryptionFilter(e,
																 new StringSink(cipher_header)
					 ) // StreamTransformationFilter
		); // StringSource
		send_iv->Assign(reinterpret_cast<const uint8_t *>(cipher_header.substr(cipher_header.length() - AES::BLOCKSIZE,
																			   AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
		e.SetKeyWithIV(*send_key, send_key->size(), *send_iv, send_iv->size());
		StringSource(content.data(), header.data_length, true,
					 new CryptoPP::AuthenticatedEncryptionFilter(e,
																 new StringSink(cipher_body)
					 ) // StreamTransformationFilter
		); // StringSource
		send_iv->Assign(reinterpret_cast<const uint8_t *>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE,
																			 AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
	} catch(CryptoPP::Exception &e) {
		std::cerr << "Caught exception (encryption): " << e.what() << std::endl;
		throw e;
	}

	cipher_all.append(cipher_header);
	cipher_all.append(cipher_body);
	int sent = 0;
	size_t to_send = cipher_all.length();

	try {
		sent = sock->Send(reinterpret_cast<const uint8_t *>(cipher_all.data()), to_send, 0);
		DEBUG("to send (w/headers): " << to_send << "; sent = " << sent);
	} catch(CryptoPP::Exception &e) {
		std::cerr << "Caught exception (net): " << e.what() << std::endl;
		throw e;
	}
}

// Receives message from connection. Modifies connection IV in preparation for the next packet.
Message Connection::recv_packet() {
	tlock lock(*recv_mutex);
	int get, rcv;
	CryptoPP::GCM<AES>::Decryption d;

	// header data recv
	const int head_enc_size = (sizeof(header_t)) + AES::BLOCKSIZE;
	get = 0;
	rcv = 0;
	unsigned char buf_head[head_enc_size];
	memset(buf_head, 0, head_enc_size);

	do {
		get = sock->Receive(&buf_head[rcv], head_enc_size - rcv, 0);
		if(get == 0) { // The other side closed the connection
			throw std::runtime_error("Error receiving packet.");
		}
		rcv += get;
	} while(head_enc_size - rcv > 0);

	// header decrypt
	std::string cipher_head, recovered_head;
	string_set(&cipher_head, buf_head, head_enc_size);

	d.SetKeyWithIV(*recv_key, recv_key->size(), *recv_iv, recv_iv->size());
	try {
		StringSource s(cipher_head, true,
					   new CryptoPP::AuthenticatedDecryptionFilter(d,
																   new StringSink(recovered_head)
					   ) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception &e) {
		std::cerr << "Caught exception (decryption): " << e.what() << std::endl;
		throw e;
	}
	header_t header;
	std::memcpy(&header, recovered_head.c_str(), (sizeof(header_t)));

	// body data recv
	int body_enc_size = header.data_length + AES::BLOCKSIZE;
	get = 0;
	rcv = 0;
	uint8_t *p_body = new uint8_t[header.data_length + CryptoPP::AES::BLOCKSIZE];
	do {
		get = sock->Receive(p_body + rcv, body_enc_size - rcv, 0);
		if(get == 0) { // The other side closed the connection
			delete[] p_body;
			throw std::runtime_error("Error receiving packet.");
		}
		rcv += get;
	} while(body_enc_size - rcv > 0);

	// body decrypt
	std::string cipher_body;
	std::vector<uint8_t> recovered_body(header.data_length);
	string_set(&cipher_body, p_body, rcv);
	delete[] p_body;

	recv_iv->Assign(reinterpret_cast<const uint8_t *>(cipher_head.substr(cipher_head.length() - AES::BLOCKSIZE,
																		 AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
	d.SetKeyWithIV(*recv_key, recv_key->size(), *recv_iv, recv_iv->size());
	try {
		StringSource s(cipher_body, true,
					   new CryptoPP::AuthenticatedDecryptionFilter(d,
																   new ArraySink(recovered_body.data(),
																				 header.data_length)
					   ) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception &e) {
		std::cerr << "Caught exception (decryption): " << e.what() << std::endl;
		throw e;
	}
	recv_iv->Assign(reinterpret_cast<const uint8_t *>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE,
																		 AES::BLOCKSIZE).data()), AES::BLOCKSIZE);

	assert(header.data_length == recovered_body.size());
//	Message message(header, recovered_body.c_str());
	return {header.packet_type, std::move(recovered_body)};
}

unsigned int Connection::buffer_size() {
	return buffer->size();
}

int Connection::buffer_read(uint8_t *p, int size) {
	int i = 0;
	while(i < size && !buffer->empty()) {
		*(p + i) = buffer->front();
		buffer->pop_front();
		i++;
	}
	return i;
}

void Connection::buffer_write(std::vector<uint8_t> data) {
	for(unsigned int i = 0; i < data.size(); i++)
		buffer->push_back(data.at(i));
}

void Connection::callback_data(std::vector<uint8_t> data) {
	bindy->callback_data(this->conn_id, data);
}

user_vector_t extract_from_old_config(std::string filename) {
    std::ifstream is (filename.data(), std::ifstream::binary);
    if(is.good()) {
        is.seekg (0, is.end);
        //std::streampos length = is.tellg();
        is.seekg (0, is.beg);
    } else {
        throw std::runtime_error("bad binary config file");
    }

    user_vector_t users;
    int count = 0;
    while(true) {
        user_t user;

        memset(&user.uid, 0, sizeof(user_id_t));
        is.read(reinterpret_cast<char *>(&user.uid), AUTH_DATA_LENGTH);
        user.name = std::string(reinterpret_cast<char *>(&user.uid));
        is.read(reinterpret_cast<char *>(&user.key), AES_KEY_LENGTH);

        user.role = static_cast<role_id_t>(count == 0 ? 1 : 2);

        if(is.good()) {
            users.push_back(std::move(user));
        } else {
            break;
        }

        count++;
    }
    is.close();

    return std::move(users);
}

user_t get_old_master() {
    auto users = extract_from_old_config("/tmp/bindy/sample_keyfile.bin");
    return users[0];
}

void Connection::initial_exchange(bcast_data_t bcast_data) {
//	std::string remote_nodename;

	bool use_bcast = (sock == nullptr);

	if(!inits_connect) { // this party accepts the connection
		// Initial exchange
		uint8_t auth_data[AUTH_DATA_LENGTH];
		memset(auth_data, 0, AUTH_DATA_LENGTH);
		if(use_bcast) {
			std::memcpy(auth_data, reinterpret_cast<const void *>(&bcast_data.data.at(0)), AUTH_DATA_LENGTH);
		}
		else {
			sock->Receive(auth_data, AUTH_DATA_LENGTH, 0);
		}

		// Authorization happens here
		user_id_t uid;
		std::memcpy(&uid, auth_data, sizeof(user_id_t));
		aes_key_t key = bindy->key_by_uid(uid);

		send_key->Assign(key.bytes, AES_KEY_LENGTH);
		recv_key->Assign(key.bytes, AES_KEY_LENGTH);

		if(use_bcast) {
			std::memcpy(recv_iv->BytePtr(), reinterpret_cast<const void *>(&bcast_data.data.at(AUTH_DATA_LENGTH)),
				   AES_KEY_LENGTH);
		}
		else {
			sock->Receive(recv_iv->BytePtr(), AES_KEY_LENGTH, 0);
		}
		send_iv->Assign(*recv_iv);

		// The tcp socket is still null, connect it first
		if(use_bcast) {
			sock = new Socket();
			sock->Create(SOCK_STREAM);
			DEBUG("Connecting to " << bcast_data.addr);
			if(!sock->Connect(bcast_data.addr.c_str(), bindy->port())) {
				DEBUG("Connect fail");
			}
			else {
				DEBUG("Connect ok");
			}
		}

		auto m_recv1 = recv_packet();
//		remote_nodename = m_recv1.second();

		std::string nodename = bindy->get_nodename();
		send_packet(link_pkt::PacketInitReply, {nodename.begin(), nodename.end()});

		auto m_recv2 = recv_packet();

		send_packet(link_pkt::PacketLinkInfo, {});
	} else { // this party initiates the connection
		CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock(*send_iv, send_iv->size());
		recv_iv->Assign(*send_iv);

		// Authorize ourselves here
		user_t master = bindy->get_master();
//        user_t master = get_old_master();
//        bool error = (
//            memcmp(master.uid.bytes, new_master.uid.bytes, AES_KEY_LENGTH)
//        );

		send_key->Assign(master.key.bytes, AES_KEY_LENGTH);
		recv_key->Assign(master.key.bytes, AES_KEY_LENGTH);


		uint8_t auth_data[AUTH_DATA_LENGTH];
		memset(auth_data, 0, AUTH_DATA_LENGTH);
//		std::string mname = bindy->get_master_login_username();
		std::memcpy(auth_data, &master.uid, sizeof(user_id_t));
		if(use_bcast) {
			uint8_t bc_packet[AUTH_DATA_LENGTH + AES_KEY_LENGTH];
			std::memcpy(bc_packet, auth_data, AUTH_DATA_LENGTH);
			std::memcpy(bc_packet + AUTH_DATA_LENGTH, send_iv->BytePtr(), AES_KEY_LENGTH);
			// accept incoming connection(s?) from server(s?) who will hear our broadcast and want to talk back
			Socket listen_sock;
			listen_sock.Create(SOCK_STREAM);
			set_socket_reuseaddr(&listen_sock);
			listen_sock.Bind(bindy->port_, NULL);
			listen_sock.Listen();

			// send a broadcast itself
			Socket bcast_sock;
			bcast_sock.Create(SOCK_DGRAM);
			set_socket_broadcast(&bcast_sock);
			std::string addr("255.255.255.255"); // todo check: does this properly route on lin & win?
			if(!bcast_sock.Connect(addr.c_str(), bindy->port_)) {
				throw std::runtime_error("Error establishing connection.");
			}
			bcast_sock.Send(bc_packet, sizeof(bc_packet), 0);
			bcast_sock.CloseSocket();

			// wait for reply
			timeval t;
			t.tv_sec = 5;
			t.tv_usec = 0;
			if(listen_sock.ReceiveReady(&t)) {
				sock = new Socket();
				sock->Create(SOCK_STREAM);
				listen_sock.Accept(*sock); // The sock is now connected, use it to continue exchange
			}
			else { // we timed out and no one wanted to talk to us
				throw std::runtime_error("Timeout waiting for broadcast reply.");
			}

			listen_sock.CloseSocket();
		}
		else {
			sock->Send(auth_data, AUTH_DATA_LENGTH, 0);
			sock->Send((const uint8_t *) (send_iv->BytePtr()), AES_KEY_LENGTH, 0);
		}

		std::string nodename = bindy->get_nodename();
		send_packet(link_pkt::PacketInitRequest, {nodename.begin(), nodename.end()});

		auto m_recv1 = recv_packet();
//		remote_nodename = m_recv1.data_string();

		send_packet(link_pkt::PacketLinkInfo, {});

		auto m_recv2 = recv_packet();
	}
}

in_addr Connection::get_ip() {
	in_addr ip;
	sockaddr psa;
	CryptoPP::socklen_t psaLen = sizeof(psa);

	sock->GetPeerName(&psa, &psaLen);
	if(psa.sa_family == AF_INET)
		ip = ((sockaddr_in *) &psa)->sin_addr;
	else
		ip.s_addr = INADDR_NONE;
	return ip;
}

void Connection::disconnect_self() {
	bindy->disconnect(conn_id);
}

Message ack_failure_from(const std::string &text) {
	return Message{link_pkt::PacketAckFailure, {text.begin(), text.end()}};
}

Message on_add_user_remote(conn_id_t conn_id, Bindy &bindy, std::vector<uint8_t> &request) {
	if(request.size() != USERNAME_LENGTH + AES_KEY_LENGTH) {
		return ack_failure_from("incorrect message length");
	}

	uint8_t *request_cursor = request.data();

	std::string username;
	aes_key_t key;

	// we assume that names are either null-terminated or occupy whole USERNAME_LENGTH
	unsigned int name_length = 0;
	while(request_cursor[name_length] != '\0' && name_length < USERNAME_LENGTH) {
		name_length++;
	}
	username = std::string(reinterpret_cast<const char *>(request_cursor), name_length);
	request_cursor += USERNAME_LENGTH;

	std::memcpy(key.bytes, request_cursor, AES_KEY_LENGTH);
	request_cursor += AES_KEY_LENGTH;

	try {
		user_id_t uid = bindy.add_user_local(username, key);

		std::vector<uint8_t> reply;
		reply.resize(sizeof(user_id_t));

		uint8_t *reply_cursor = reply.data();

		std::memcpy(reply_cursor, &uid, sizeof(user_id_t));
		reply_cursor += sizeof(user_id_t);

		return Message{link_pkt::PacketAckSuccess, std::move(reply)};
	} catch(std::runtime_error &e) {
		return ack_failure_from(e.what());
	} catch(...) {
		return ack_failure_from("unknow generic error");
	}
}

Message on_del_user_remote(conn_id_t conn_id, Bindy &bindy, std::vector<uint8_t> &request) {
	if(request.size() != sizeof(user_id_t))
		return ack_failure_from("incorrect message length");

	uint8_t *request_cursor = request.data();

	user_id_t uid;

	std::memcpy(&uid, request_cursor, sizeof(user_id_t));
	request_cursor += sizeof(user_id_t);

	try {
		bindy.del_user_local(uid);
		return Message{link_pkt::PacketAckSuccess, {}};
	} catch(std::runtime_error &e) {
		return ack_failure_from(e.what());
	} catch(...) {
		return ack_failure_from("unknow generic error");
	}
}

Message on_change_key_remote(conn_id_t conn_id, Bindy &bindy, std::vector<uint8_t> &request) {
	if(request.size() != sizeof(user_id_t) + AES_KEY_LENGTH)
		return ack_failure_from("incorrect message length");

	uint8_t *request_cursor = request.data();

	user_id_t uid;
	aes_key_t key;

	std::memcpy(&uid, request_cursor, sizeof(user_id_t));
	request_cursor += sizeof(user_id_t);

	std::memcpy(key.bytes, request_cursor, AES_KEY_LENGTH);
	request_cursor += AES_KEY_LENGTH;

	try {
		bindy.change_key_local(uid, key);
		return Message{link_pkt::PacketAckSuccess, {}};
	} catch(std::runtime_error &e) {
		return ack_failure_from(e.what());
	} catch(...) {
		return ack_failure_from("unknow generic error");
	}
}

Message on_list_users_remote(conn_id_t conn_id, Bindy &bindy, std::vector<uint8_t> &request) {
	if(request.size() != 0) {
		return ack_failure_from("incorrect message length");
	}

	try {
		user_vector_t users = bindy.list_users_local();
		size_t user_size = sizeof(user_id_t) + USERNAME_LENGTH + AES_KEY_LENGTH + sizeof(role_id_t);

		std::vector<uint8_t> reply(user_size * users.size());
		uint8_t *reply_cursor = reply.data();

		for(unsigned int i = 0; i < users.size(); i++) {
			user_t &user = users[i];
			std::memcpy(reply_cursor, &user.uid, sizeof(user_id_t));
			reply_cursor += sizeof(user_id_t);
			std::memcpy(reply_cursor, user.name.data(), USERNAME_LENGTH);
			reply_cursor += USERNAME_LENGTH;
			std::memcpy(reply_cursor, &user.key, AES_KEY_LENGTH);
			reply_cursor += AES_KEY_LENGTH;
			std::memcpy(reply_cursor, &user.role, sizeof(role_id_t));
			reply_cursor += sizeof(role_id_t);
		}

		return Message{link_pkt::PacketAckSuccess, std::move(reply)};
	} catch(std::runtime_error &e) {
		return ack_failure_from(e.what());
	} catch(...) {
		return ack_failure_from("unknow generic error");
	}
}

Message on_set_master_remote(conn_id_t conn_id, Bindy &bindy, std::vector<uint8_t> &request) {
	if(request.size() != sizeof(user_id_t))
		return ack_failure_from("incorrect message length");

	uint8_t *request_cursor = request.data();

	user_id_t uid;

	std::memcpy(&uid, request_cursor, sizeof(user_id_t));
	request_cursor += sizeof(user_id_t);

	try {
		bindy.set_master_local(uid);

		return Message{link_pkt::PacketAckSuccess, {}};
	} catch(std::runtime_error &e) {
		return ack_failure_from(e.what());
	} catch(...) {
		return ack_failure_from("unknow generic error");
	}
}

void socket_thread_function(void *arg) {
	Connection *conn = nullptr;
	try {
		conn = new Connection((Connection *) arg);
		while(true) {
			Message request(conn->recv_packet());

			if(request.type == link_pkt::PacketTermRequest) {
				// FIXME: cleaner solution for connection termination?
				throw std::runtime_error("Connection close request received");
			} else if(request.type == link_pkt::PacketData) {
				conn->callback_data(request.content);
				// Internal administration protocol handling
			} else {
				// we assume that last bytes are message uid
				ack_id_t msg_id;
				unsigned long orig_request_size = request.content.size() - sizeof(ack_id_t);
				std::memcpy(&msg_id, request.content.data() + orig_request_size, sizeof(ack_id_t));
				request.content.resize(orig_request_size);

				if(request.type == link_pkt::PacketAckSuccess || request.type == link_pkt::PacketAckFailure) {
					Message &reply = request;
					// don't execute callback under mutex
					conn->ack_mutex->lock();
					auto handlers = std::move(conn->ack_callbacks->at(msg_id));
					conn->ack_callbacks->erase(msg_id);
					conn->ack_mutex->unlock();
					request.type == link_pkt::PacketAckSuccess ? handlers.first(reply.content) : handlers.second(reply.content);
				} else {
//					link_pkt reply_type;
					Message reply;
					if(request.type == link_pkt::PacketAddUser) {
						reply = on_add_user_remote(conn->conn_id, *conn->bindy, request.content);
					} else if(request.type == link_pkt::PacketDelUser) {
						reply = on_del_user_remote(conn->conn_id, *conn->bindy, request.content);
					} else if(request.type == link_pkt::PacketChangeKey) {
						reply = on_change_key_remote(conn->conn_id, *conn->bindy, request.content);
					} else if(request.type == link_pkt::PacketListUsers) {
						reply = on_list_users_remote(conn->conn_id, *conn->bindy, request.content);
					} else if(request.type == link_pkt::PacketSetMaster) {
						reply = on_set_master_remote(conn->conn_id, *conn->bindy, request.content);
					}

					unsigned long orig_reply_size = reply.content.size();
					reply.content.resize(orig_reply_size + sizeof(ack_id_t));
					std::memcpy(reply.content.data() + orig_reply_size, &msg_id, sizeof(ack_id_t));
					conn->send_packet(reply.type, reply.content);
				}
			}
		};
	} catch(...) {
		DEBUG("Caught exception, deleting connection...");
	}
	conn->disconnect_self();
	delete conn;
}


bool set_socket_keepalive_nodelay(Socket *s) {
	bool ok = true;

#if defined (WIN32) || defined(WIN64)
	/*
const char optval = 1;
tcp_keepalive lpvInBuffer;
int cbInBuffer = sizeof(lpvInBuffer);
lpvInBuffer.onoff = 1;
lpvInBuffer.keepalivetime = KEEPIDLE;
lpvInBuffer.keepaliveinterval = KEEPINTVL;
//	lpvInBuffer.keepalivecount = KEEPCNT;  There is no such thing in windows. Stupid windows.
ok &= (0 == WSAIoctl(
  *s,              // descriptor identifying a socket
  SIO_KEEPALIVE_VALS,                  // dwIoControlCode
  &lpvInBuffer,    // pointer to tcp_keepalive struct
  cbInBuffer,      // length of input buffer
  NULL,         // output buffer
  0,       // size of output buffer
  NULL,    // number of bytes returned
  NULL,   // OVERLAPPED structure
  NULL  // completion routine
) );
ok &= ( 0 == setsockopt(*s, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(int)) );
*/
#else
	unsigned int result;

	int optval = 1; // 1 == enable option
	int keepalive_intvl = KEEPINTVL;
	int keepalive_idle = KEEPIDLE;
	int keepalive_cnt = KEEPCNT;

	ok &= (0 == setsockopt(*s, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int)));
	// TODO non-portable line of code
#ifdef __linux__
	ok &= (0 == setsockopt(*s, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(int)));
	ok &= (0 == setsockopt(*s, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle, sizeof(int)));
	ok &= (0 == setsockopt(*s, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_cnt, sizeof(int)));
#endif

	// Also disable Nagle, because we want faster response and each bindy packet is a complete packet that should be wrapped in TCP and sent right away
	optval = 1;
	ok &= (0 == setsockopt(*s, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(int)));
#endif
	return ok;
}

void main_thread_function(void *arg) {
	Bindy *bindy = (Bindy *) arg;

	Socket listen_sock;
	try {
		DEBUG("Creating TCP listen socket...");
		listen_sock.Create(SOCK_STREAM);
		set_socket_reuseaddr(&listen_sock);
		listen_sock.Bind(bindy->port(), NULL);
	} catch(std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
		throw e;
	}
	if(!set_socket_keepalive_nodelay(
		&listen_sock)) { // all connection sockets inherit required options from listening socket
		std::cerr << "Could not set socket options." << std::endl;
		throw std::runtime_error("setsockopt failed");
	}
	listen_sock.Listen();

	try {
		while(true) {
			Socket *sock = new Socket;
			sock->Create(SOCK_STREAM);
			listen_sock.Accept(*sock);

			conn_id_t local_conn_id;
			{
				tlock lock(bindy->bindy_state_->interlock_mutex);
				local_conn_id = listen_conn_id;
				listen_conn_id++;
			}

			try {
				bcast_data_t empty;
				empty.addr = std::string();
				empty.data = std::vector<uint8_t>();
				SuperConnection *sc = new SuperConnection(bindy, sock, local_conn_id, false, empty);
				bindy->add_connection(local_conn_id, sc);
			}
			catch(...) {
				DEBUG(
					"Error creating and/or initializing connection in main_thread");; /// failed connection attempt either due to key being rejected or ... ?
			}
		}
	} catch(std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
	}
	listen_sock.CloseSocket();
}

void broadcast_thread_function(void *arg) {
	Bindy *bindy = (Bindy *) arg;

	Socket bcast_sock;
	try {
		DEBUG("Creating UDP listen socket...");
		bcast_sock.Create(SOCK_DGRAM);
		set_socket_broadcast(&bcast_sock);
		bcast_sock.Bind(bindy->port(), NULL);
	} catch(std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
		throw e;
	}

	bool recv_ok = true;
	try {
		while(recv_ok) {
			char setuprq[AUTH_DATA_LENGTH + AES_KEY_LENGTH];
			// unsigned int size = bcast_sock.Receive(setuprq, sizeof (setuprq), NULL);
			// Cannot use Cryptopp wrapper here because it doesn't provide src addr for broadcasts
			struct sockaddr from;
			socklen_t fromlen = sizeof(from);
			unsigned int size = recvfrom(bcast_sock, setuprq, sizeof(setuprq), 0, &from, &fromlen);
			struct sockaddr_in from_in = *(sockaddr_in *) &from;
			std::string addrbuf;
			if(from.sa_family == AF_INET) {
				addrbuf = inet_ntoa(from_in.sin_addr);
				DEBUG("received broadcast from " << addrbuf << ", size = " << size);
			}
			else {
				DEBUG("unknown address family");
				break;
			}

			conn_id_t local_conn_id;
			{
				tlock lock(bindy->bindy_state_->interlock_mutex);
				local_conn_id = listen_conn_id;
				listen_conn_id++;
			}

			try {
				bcast_data_t not_empty;
				not_empty.addr = addrbuf;
				not_empty.data = std::vector<uint8_t>(setuprq, setuprq + size);
				SuperConnection *sc = new SuperConnection(bindy, nullptr, local_conn_id, false, not_empty);
				bindy->add_connection(local_conn_id, sc);
			}
			catch(...) {
				DEBUG(
					"Error creating and/or initializing connection in broadcast_thread");; /// failed connection attempt either due to key being rejected or ... ?
			}
		}
	} catch(std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
	}
	bcast_sock.CloseSocket();
}

aes_key_t Bindy::key_by_uid(const user_id_t& uid) {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"SELECT key FROM Users WHERE uuid=?;"
	);

	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt); throw std::runtime_error(sqlite3_errmsg(db));
	}

	auto test = sqlite3_bind_blob(stmt, 1, &uid, sizeof(user_id_t), SQLITE_TRANSIENT);

	// mapping <Table name>.<Column name> to numerical index
	std::map<std::string, int> index;
	for(int i = sqlite3_column_count(stmt) - 1; i >= 0; i--) {
		index[std::string(sqlite3_column_table_name(stmt, i)) + "." + std::string(sqlite3_column_name(stmt, i))] = i;
	}

	int cr = sqlite3_step(stmt);

	if(cr != SQLITE_ROW) {
		sqlite3_finalize(stmt); throw std::runtime_error("key not found");
	}

	aes_key_t result;
	memset(result.bytes, 0, AES_KEY_LENGTH);
	std::memcpy(result.bytes, sqlite3_column_blob(stmt, index["Users.key"]), sizeof(aes_key_t));
	// ensure that there is only one user with such uid;
	// if cr != SQLITE_DONE then database is probably corrupted
	cr = sqlite3_step(stmt);

	sqlite3_finalize(stmt);

	if(cr != SQLITE_DONE) {
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	return result;
}

user_id_t uuid_to_uid(sole::uuid&& uuid) {
	user_id_t uid;
	memset(uid.bytes, 0, sizeof(user_id_t));
	memcpy(uid.bytes, &uuid, sizeof(sole::uuid));
	return uid;
}

void init_db(sqlite3 *db, const user_vector_t &users={}) {
	sqlite3_stmt *stmt;
	std::stringstream query_stream;

	std::vector<std::string> static_statements{
		"CREATE TABLE Users (uuid TEXT UNIQUE NOT NULL PRIMARY KEY, name TEXT NOT NULL, role INTEGER NOT NULL, key BLOB (16) NOT NULL UNIQUE);",
		"CREATE TRIGGER SingleMasterInsert BEFORE INSERT ON Users FOR EACH ROW WHEN NEW.role = 1 BEGIN SELECT RAISE (ABORT, 'master already exists') WHERE EXISTS(SELECT 1 FROM Users WHERE role = 1); END;",
		"CREATE TRIGGER SingleMasterUpdate BEFORE UPDATE OF role ON Users FOR EACH ROW WHEN NEW.role = 1  BEGIN SELECT RAISE (ABORT, 'master already exists') WHERE EXISTS(SELECT 1 FROM Users WHERE role = 1); END;",
	};

	for(std::string &s : static_statements) {
		query_stream << s;
	}

    if(users.size() > 0) {
        query_stream << "BEGIN;";
        query_stream << "INSERT INTO Users VALUES ";
        short int i = 0;
        for(const user_t &user : users) {
            assert(user.role == 1 || user.role == 2);
            query_stream << "(?, ?, " << (user.role==1 ? "1" : "2") << ", ?)";
            query_stream << (i < users.size()-1 ? "," : ";");
            i++;
        }
        query_stream << "COMMIT;";
    }

	// FIXME: performs full copy
	auto query = query_stream.str();
	const char *left = query.data();
	uint8_t statement = 0;
	do {
		if(sqlite3_prepare_v2(db, left, -1, &stmt, &left) != SQLITE_OK) {
			sqlite3_finalize(stmt); throw std::runtime_error(sqlite3_errmsg(db));
		}

		if(statement == static_statements.size()) {
			unsigned int bind_index = 1;
			for(auto& user: users) {
				sqlite3_bind_blob(stmt, bind_index++, &user.uid, sizeof(user_id_t), SQLITE_TRANSIENT);
				sqlite3_bind_text(stmt, bind_index++, user.name.data(), AUTH_DATA_LENGTH, SQLITE_TRANSIENT);
				sqlite3_bind_blob(stmt, bind_index++, &user.key, AES_KEY_LENGTH, SQLITE_TRANSIENT);
			}
		}

		int cr = sqlite3_step(stmt);
		if(cr != SQLITE_DONE) {
			sqlite3_finalize(stmt); throw std::runtime_error(sqlite3_errmsg(db));
		}

		statement++;
	} while(left[0] != '\0');

	sqlite3_finalize(stmt);

	DEBUG("Database initialized)");
}

Bindy::Bindy(std::string filename, bool is_server, bool is_buffered)
	:
	port_(49150), is_server_(is_server), is_buffered_(is_buffered) {
	bindy_state_ = new BindyState();
	bindy_state_->m_datasink = nullptr;
	bindy_state_->m_discnotify = nullptr;
	bindy_state_->main_thread = nullptr;
	bindy_state_->bcast_thread = nullptr;

	if(AES_KEY_LENGTH != CryptoPP::AES::DEFAULT_KEYLENGTH) {
		throw std::logic_error("AES misconfiguration, expected AES-128");
	}

    if(filename.empty()) DEBUG("Opening temporary in-memory keyfile");
	if(sqlite3_open_v2(filename.data(), &(bindy_state_->sql_conn), SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
		sqlite3_close(bindy_state_->sql_conn);
		throw std::runtime_error("cannot open sqlite");
	}
	try {
		init_db(bindy_state_->sql_conn);
	} catch (std::runtime_error &e) {
		// skip
	}
};

Bindy::~Bindy() {
	if(is_server_) {
		if(bindy_state_->main_thread != nullptr)
			bindy_state_->main_thread->join();
		if(bindy_state_->bcast_thread != nullptr)
			bindy_state_->bcast_thread->join();
	}

	sqlite3_close(bindy_state_->sql_conn);

	delete bindy_state_->main_thread;
	delete bindy_state_->bcast_thread;
	delete bindy_state_;
};

user_id_t Bindy::add_user_local(const std::string &username, const aes_key_t &key) {
    user_id_t uid = uuid_to_uid(sole::uuid1());
    return add_user_local(username, key, uid);
}

user_id_t Bindy::add_user_local(const std::string &username, const aes_key_t &key, const user_id_t &uid) {
	if(username.length() > USERNAME_LENGTH)
		throw std::runtime_error("name too long");

	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"INSERT INTO Users VALUES(?, ?, 2, ?);"
	);

	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	sqlite3_bind_blob(stmt, 1, &uid, sizeof(user_id_t), SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, username.data(), static_cast<int>(username.size()), SQLITE_TRANSIENT);
	sqlite3_bind_blob(stmt, 3, key.bytes, AES_KEY_LENGTH, SQLITE_TRANSIENT);

	int cr = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if(cr != SQLITE_DONE) {
		throw std::runtime_error(sqlite3_errmsg(db));
	}
	DEBUG("User created(uid: " << uid.bytes << ")");

	return uid;
}

void Bindy::del_user_local(const user_id_t &uid) {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"DELETE FROM Users WHERE uuid=?;"
	);

	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	sqlite3_bind_blob(stmt, 1, &uid, sizeof(user_id_t), SQLITE_TRANSIENT);

	int cr = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if(cr != SQLITE_DONE) {
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	DEBUG("User deleted(uid: " << uid.bytes << ")");
}

void Bindy::change_key_local(const user_id_t &uid, const aes_key_t &key) {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"UPDATE Users SET key=? WHERE uuid=?;"
	);

	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	sqlite3_bind_blob(stmt, 1, key.bytes, AES_KEY_LENGTH, SQLITE_TRANSIENT);
	sqlite3_bind_blob(stmt, 2, &uid, sizeof(user_id_t), SQLITE_TRANSIENT);

	int cr = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if(cr != SQLITE_DONE) {
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	DEBUG("User key changed(uid: " << uid.bytes << ")");
}

user_vector_t Bindy::list_users_local() {
	return list_users_local([](user_t user) { return true; });
}

user_vector_t Bindy::list_users_local(std::function<bool(user_t &user)> filter) {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"SELECT uuid, name, role, key FROM Users;"
	);

	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	// mapping <Table name>.<Column name> to numerical index
	std::map<std::string, int> index;
	for(int i = sqlite3_column_count(stmt) - 1; i >= 0; i--) {
		index[std::string(sqlite3_column_table_name(stmt, i)) + "." + std::string(sqlite3_column_name(stmt, i))] = i;
	}

	std::vector<user_t> result;

	int cr;
	while(true) {
		cr = sqlite3_step(stmt);
		if(cr != SQLITE_ROW) break;

		user_t user;

		std::memcpy(&user.uid, sqlite3_column_blob(stmt, index["Users.uuid"]), sizeof(user_id_t));
		user.name.assign(reinterpret_cast<const char *>(sqlite3_column_text(stmt, index["Users.name"])));
		std::memcpy(&user.key, sqlite3_column_blob(stmt, index["Users.key"]), AES_KEY_LENGTH);
		user.role = static_cast<role_id_t>(sqlite3_column_int(stmt, index["Users.role"]));

		if(filter(user))
			result.push_back(std::move(user));
	}

	sqlite3_finalize(stmt);

	if(cr != SQLITE_DONE) {
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	return std::move(result);
}

void Bindy::set_master_local(const user_id_t &uid) {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"BEGIN;"
		"UPDATE Users SET role=2 WHERE role=1;"
		"UPDATE Users SET role=1 WHERE uuid=?;"
		"COMMIT;"
	);

	const char *left = query.data();
	uint8_t statement = 0;
	do {
		if(sqlite3_prepare_v2(db, left, -1, &stmt, &left) != SQLITE_OK) {
			sqlite3_finalize(stmt);
			throw std::runtime_error(sqlite3_errmsg(db));
		}

		if(statement == 2)
			sqlite3_bind_blob(stmt, 1, &uid, sizeof(user_id_t), SQLITE_TRANSIENT);

		int cr = sqlite3_step(stmt);
		if(cr != SQLITE_DONE) {
			sqlite3_finalize(stmt);
			throw std::runtime_error(sqlite3_errmsg(db));
		}

		statement++;
	} while(left[0] != '\0');

	sqlite3_finalize(stmt);

	DEBUG("Master user changed(uid: " << uid.bytes << ")");
}

std::exception_ptr exception_from_reply(const std::vector<uint8_t> &reply) {
	uint8_t length;
	std::memcpy(&length, reply.data(), sizeof(uint8_t));
	std::string error_text(reinterpret_cast<const char *>(reply.data()) + sizeof(uint8_t), length);
	return std::make_exception_ptr(std::runtime_error(error_text));
}

std::future<user_id_t> Bindy::add_user_remote(const conn_id_t conn_id, const std::string &username, const aes_key_t &key) {
	if(username.length() > USERNAME_LENGTH) {
		throw std::runtime_error("Username is too long");
	}
	tlock bindy_lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) != 1) {
		throw std::runtime_error("Connection not found");
	}
	SuperConnection *sconn = bindy_state_->connections[conn_id];

	// Serialization
	size_t estimated = USERNAME_LENGTH + AES_KEY_LENGTH;
	std::vector<uint8_t> content;
	content.resize(estimated);

	uint8_t *cursor = content.data();

	memset(cursor, 0, USERNAME_LENGTH);
	std::memcpy(cursor, username.data(), username.length());
	cursor += USERNAME_LENGTH;
	std::memcpy(cursor, key.bytes, AES_KEY_LENGTH);
	cursor += AES_KEY_LENGTH;

	assert((cursor - content.data()) == estimated);

	auto completion = std::make_shared<std::promise<user_id_t>>();

	// Reply handlers
	ack_callback_t success = [completion](const std::vector<uint8_t> &reply) {
		user_id_t new_user_id;
		std::memcpy(&new_user_id, reply.data(), sizeof(user_id_t));
		completion->set_value(new_user_id);
	};
	ack_callback_t failure = [completion](const std::vector<uint8_t> &reply) {
		completion->set_exception(exception_from_reply(reply));
	};

	sconn->send_packet_ack(link_pkt::PacketAddUser, content, success, failure);

	return completion->get_future();
}


std::future<void> Bindy::del_user_remote(const conn_id_t conn_id, const user_id_t &uid) {
	tlock bindy_lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) != 1) {
		throw std::runtime_error("Connection not found");
	}
	SuperConnection *sconn = bindy_state_->connections[conn_id];

	// Serialization
	size_t estimated = sizeof(user_id_t);
	std::vector<uint8_t> content;
	content.resize(estimated);

	uint8_t *cursor = content.data();

	std::memcpy(cursor, &uid, sizeof(user_id_t));
	cursor += sizeof(user_id_t);

	assert((cursor - content.data()) == estimated);

	auto completion = std::make_shared<std::promise<void>>();

	// Reply handlers
	ack_callback_t success = [completion](const std::vector<uint8_t> &reply) {
		completion->set_value();
	};
	ack_callback_t failure = [completion](const std::vector<uint8_t> &reply) {
		completion->set_exception(exception_from_reply(reply));
	};

	sconn->send_packet_ack(link_pkt::PacketDelUser, content, success, failure);

	return completion->get_future();
}

std::future<void> Bindy::change_key_remote(const conn_id_t conn_id, const user_id_t &uid, const aes_key_t &key) {
	tlock bindy_lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) != 1) {
		throw std::runtime_error("Connection not found");
	}
	SuperConnection *sconn = bindy_state_->connections[conn_id];

	// Serialization
	size_t estimated = sizeof(user_id_t) + AES_KEY_LENGTH;
	std::vector<uint8_t> content;
	content.resize(estimated);

	uint8_t *cursor = content.data();

	std::memcpy(cursor, &uid, sizeof(user_id_t));
	cursor += sizeof(user_id_t);
	std::memcpy(cursor, key.bytes, AES_KEY_LENGTH);
	cursor += AES_KEY_LENGTH;

	assert((cursor - content.data()) == estimated);

	auto completion = std::make_shared<std::promise<void>>();

	// Reply handlers
	ack_callback_t success = [completion](const std::vector<uint8_t > &reply) {
		completion->set_value();
	};
	ack_callback_t failure = [completion](const std::vector<uint8_t> &reply) {
		completion->set_exception(exception_from_reply(reply));
	};

	sconn->send_packet_ack(link_pkt::PacketChangeKey, content, success, failure);

	return completion->get_future();
}

std::future<user_vector_t> Bindy::list_users_remote(const conn_id_t conn_id) {
	tlock bindy_lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) != 1) {
		throw std::runtime_error("Connection not found");
	}
	SuperConnection *sconn = bindy_state_->connections[conn_id];

	std::vector<uint8_t> content(0);

	auto completion = std::make_shared<std::promise<user_vector_t>>();

	// Reply handlers
	ack_callback_t success = [completion](const std::vector<uint8_t > &reply) {
		unsigned long user_size = sizeof(user_id_t) + USERNAME_LENGTH + AES_KEY_LENGTH + sizeof(role_id_t);
		if(reply.size() % user_size != 0) {
			completion->set_exception(std::make_exception_ptr(std::runtime_error("mailformed reply received")));
		}

		user_vector_t users;
		const uint8_t *cursor = reply.data();
		for(unsigned long i = 0; i < reply.size() / user_size; i++) {
			user_t user;

			std::memcpy(&user.uid, cursor, sizeof(user_id_t));
			cursor += sizeof(user_id_t);

			// we assume that names are either null-terminated or occupy whole USERNAME_LENGTH
			unsigned int name_length = 0;
			while(cursor[name_length] != '\0' && name_length < USERNAME_LENGTH) {
				name_length++;
			}
			user.name = std::string(reinterpret_cast<const char *>(cursor), name_length);
			cursor += USERNAME_LENGTH;

			std::memcpy(&user.key, cursor, AES_KEY_LENGTH);
			cursor += AES_KEY_LENGTH;

			std::memcpy(&user.role, cursor, sizeof(role_id_t));
			cursor += sizeof(role_id_t);

			users.push_back(std::move(user));
		}

		completion->set_value(std::move(users));
	};
	ack_callback_t failure = [completion](const std::vector<uint8_t> &reply) {
		completion->set_exception(exception_from_reply(reply));
	};

	sconn->send_packet_ack(link_pkt::PacketListUsers, content, success, failure);

	return completion->get_future();
}

std::future<void> Bindy::set_master_remote(const conn_id_t conn_id, const user_id_t &uid) {
	tlock bindy_lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) != 1) {
		throw std::runtime_error("Connection not found");
	}
	SuperConnection *sconn = bindy_state_->connections[conn_id];

	// Serialization
	size_t estimated = sizeof(user_id_t);
	std::vector<uint8_t> content;
	content.resize(estimated);

	uint8_t *cursor = content.data();

	std::memcpy(cursor, &uid, sizeof(user_id_t));
	cursor += sizeof(user_id_t);

	assert((cursor-content.data()) == estimated);

	auto completion = std::make_shared<std::promise<void>>();

	// Reply handlers
	ack_callback_t success = [completion](const std::vector<uint8_t> &reply) {
		completion->set_value();
	};
	ack_callback_t failure = [completion](const std::vector<uint8_t> &reply) {
		completion->set_exception(exception_from_reply(reply));
	};

	sconn->send_packet_ack(link_pkt::PacketSetMaster, content, success, failure);

	return completion->get_future();
}

void Bindy::import_users_from_keyfile(const std::string path) {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"ATTACH DATABASE ? AS import_user_db;"
		"BEGIN;"
		"INSERT INTO main.Users SELECT uuid, name, 2, key FROM import_user_db.Users;"
		"COMMIT;"
		"DETACH DATABASE import_user_db;"
	);
	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	const char *left = query.data();
	uint8_t statement = 0;
	do {
		if(sqlite3_prepare_v2(db, left, -1, &stmt, &left) != SQLITE_OK) {
			sqlite3_finalize(stmt);
			throw std::runtime_error(sqlite3_errmsg(db));
		}
		if(statement == 0)
			sqlite3_bind_text(stmt, 1, path.data(), static_cast<int>(path.length()), SQLITE_TRANSIENT);

		int cr = sqlite3_step(stmt);
		if(cr != SQLITE_DONE) {
			sqlite3_finalize(stmt);
			throw std::runtime_error(sqlite3_errmsg(db));
		}

		statement++;
	} while(left[0] != '\0');
}

void Bindy::export_user_to_keyfile(const user_id_t& uid, const std::string path) {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"SELECT uuid, name, role, key FROM Users WHERE Users.uuid=?;"
	);

	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt); throw std::runtime_error(sqlite3_errmsg(db));
	}

	sqlite3_bind_blob(stmt, 1, &uid, sizeof(user_id_t), SQLITE_TRANSIENT);

	// mapping <Table name>.<Column name> to numerical index
	std::map<std::string, int> index;
	for(int i = sqlite3_column_count(stmt) - 1; i >= 0; i--) {
		index[std::string(sqlite3_column_table_name(stmt, i)) + "." + std::string(sqlite3_column_name(stmt, i))] = i;
	}

	user_t user;
	user.role = 1;
	int cr = sqlite3_step(stmt);
	if(cr != SQLITE_ROW) {
		sqlite3_finalize(stmt); throw std::runtime_error("User not found");
	}
	std::memcpy(&user.uid, sqlite3_column_blob(stmt, index["Users.uuid"]), sizeof(user_id_t));
	user.name.assign(reinterpret_cast<const char *>(sqlite3_column_text(stmt, index["Users.name"])));
	std::memcpy(&user.key, sqlite3_column_blob(stmt, index["Users.key"]), AES_KEY_LENGTH);
	// this user is the only user in new database - make him master
	user.role = 1;

	cr = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if(cr != SQLITE_DONE) {
		throw std::runtime_error(
			cr == SQLITE_ROW ? "more then one user found for given uid - possible database corruption" : sqlite3_errmsg(db)
		);
	}

	sqlite3 *export_sql_conn;
	if (sqlite3_open_v2(path.data(), &(export_sql_conn), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
		sqlite3_close(export_sql_conn); throw std::runtime_error("cannot open sqlite connection for export");
	}

	init_db(export_sql_conn, {user});

	sqlite3_close(export_sql_conn);
}

void Bindy::set_handler(void (*datasink)(conn_id_t conn_id, std::vector<uint8_t> data)) {
	if(!is_buffered_)
		bindy_state_->m_datasink = datasink;
}

void Bindy::set_discnotify(void (*discnotify)(conn_id_t)) {
	if(!is_buffered_)
		bindy_state_->m_discnotify = discnotify;
}

/*!

*/
void Bindy::connect() {
	tlock lock(bindy_state_->mutex);
	if(is_server_) {
		if(bindy_state_->main_thread == nullptr) {
			bindy_state_->main_thread = new tthread::thread(main_thread_function, this);
		}
		if(bindy_state_->bcast_thread == nullptr) {
			bindy_state_->bcast_thread = new tthread::thread(broadcast_thread_function, this);
		}
	}
}

conn_id_t Bindy::connect(std::string addr) {
	int conn_id = conn_id_invalid;
	Socket *sock = nullptr;
	SuperConnection *sc = nullptr;
	if(addr.empty()) { // use broadcast to connect somewhere
		tlock lock(bindy_state_->mutex);
		do {
			conn_id = rand();
		} while(bindy_state_->connections.count(conn_id) != 0 || conn_id == conn_id_invalid);
		// uid==0==conn_id_invalid is the single invalid state, so we don't return it
		try {
			DEBUG("creating connection for udp init...");
			bcast_data_t empty;
			empty.addr = std::string();
			empty.data = std::vector<uint8_t>();
			sc = new SuperConnection(this, nullptr, conn_id, true, empty);
			bindy_state_->connections[conn_id] = sc;
		}
		catch(...) { // ?
			; // same as server listen thread
			DEBUG("Error creating and/or initializing connection in connect() over udp");
			return conn_id_invalid;
		}
	} else { // try to connect to the specified host
		try {
			DEBUG("using tcp to connect to " << addr);
			sock = new Socket();
			sock->Create(SOCK_STREAM);
			if(!sock->Connect(addr.c_str(), port_))
				throw std::runtime_error("Error establishing connection.");
		} catch(CryptoPP::Exception &e) {
			std::cerr << e.what() << std::endl;
			throw e;
		}

		{
			tlock lock(bindy_state_->mutex);
			do {
				conn_id = rand();
			} while(bindy_state_->connections.count(conn_id) != 0 || conn_id == conn_id_invalid);
			// uid==0==conn_id_invalid is the single invalid state, so we don't return it
			try {
				DEBUG("creating connection for tcp init...");
				bcast_data_t empty;
				empty.addr = std::string();
				empty.data = std::vector<uint8_t>();
				sc = new SuperConnection(this, sock, conn_id, true, empty);
				bindy_state_->connections[conn_id] = sc;
			}
			catch(...) { // ?
				; // same as server listen thread
				DEBUG("Error creating and/or initializing connection in connect() over tcp");
				return conn_id_invalid;
			}
		}
	}
	return conn_id;
}

void Bindy::send_data(conn_id_t conn_id, std::vector<uint8_t> content) {
	if(bindy_state_->connections.count(conn_id) == 1) { // should be 1 exactly...
		tlock lock(bindy_state_->mutex);
		SuperConnection *sconn = bindy_state_->connections[conn_id];
		DEBUG("sending " << content.size() << " raw bytes...");
		DEBUG("bytes =  " << hex_encode(content));
		sconn->send_packet(link_pkt::PacketData, content);
		DEBUG("data sent");
	} else {
		throw std::runtime_error("Error in send_data");
	}
}

int Bindy::read(conn_id_t conn_id, uint8_t *p, int size) {
	tlock lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) == 1) {
		return bindy_state_->connections[conn_id]->buffer_read(p, size);
	}
	return -1;
}

int Bindy::get_data_size(conn_id_t conn_id) {
	tlock lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) == 1) {
		return static_cast<int>(bindy_state_->connections[conn_id]->buffer_size());
	}
	return -1;
}

// filter MUST match single user
user_t Bindy::get_master() {
	sqlite3 *db = bindy_state_->sql_conn;
	sqlite3_stmt *stmt;

	std::string query(
		"SELECT uuid, name, role, key FROM Users WHERE Users.role=1;"
	);

	if(sqlite3_prepare_v2(db, query.data(), (int) query.length(), &stmt, 0) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		throw std::runtime_error(sqlite3_errmsg(db));
	}

	// mapping <Table name>.<Column name> to numerical index
	std::map<std::string, int> index;
	for(int i = sqlite3_column_count(stmt) - 1; i >= 0; i--) {
		index[std::string(sqlite3_column_table_name(stmt, i)) + "." + std::string(sqlite3_column_name(stmt, i))] = i;
	}

	user_t user;

	int cr = sqlite3_step(stmt);
	if(cr == SQLITE_ROW) {
		std::memcpy(&user.uid, sqlite3_column_blob(stmt, index["Users.uuid"]), sizeof(user_id_t));
		user.name.assign(reinterpret_cast<const char *>(sqlite3_column_text(stmt, index["Users.name"])));
		std::memcpy(&user.key, sqlite3_column_blob(stmt, index["Users.key"]), sizeof(aes_key_t));
		user.role = static_cast<role_id_t>(sqlite3_column_int(stmt, index["Users.role"]));
	}

	cr = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if(cr != SQLITE_DONE) {
		throw std::runtime_error(
			cr == SQLITE_ROW ? "more then one master found - possible database corruption" : sqlite3_errmsg(db)
		);
	}

	return user;
}

void Bindy::set_nodename(std::string nodename) {
	bindy_state_->nodename = nodename;
}

std::string Bindy::get_nodename(void) {
	return bindy_state_->nodename;
}

bool Bindy::is_server() {
	return is_server_;
}

int Bindy::port() {
	return port_;
}

void Bindy::add_connection(conn_id_t conn_id, SuperConnection *sconn) {
	tlock lock(bindy_state_->mutex);
	bindy_state_->connections[conn_id] = sconn;
}

void Bindy::delete_connection(conn_id_t conn_id) {
	tlock lock(bindy_state_->mutex);
	if(bindy_state_->connections.count(conn_id) == 1) {
		delete bindy_state_->connections[conn_id]; // safe, because we're under the global bindy mutex
		bindy_state_->connections.erase(conn_id);
	}
}

std::list<conn_id_t> Bindy::list_connections() {
	tlock lock(bindy_state_->mutex);
	std::list<conn_id_t> list;
	std::map<conn_id_t, SuperConnection *>::iterator it;
	for(it = bindy_state_->connections.begin(); it != bindy_state_->connections.end(); it++) {
		list.push_back(it->first);
	}
	return list;
}

void Bindy::disconnect(conn_id_t conn_id) {
	delete_connection(conn_id);
	callback_disc(conn_id);
}

void Bindy::callback_data(conn_id_t conn_id, std::vector<uint8_t> data) {
	if(is_buffered_) { // save to buffer
		tlock lock(bindy_state_->mutex);
		if(bindy_state_->connections.count(conn_id) == 1)
			bindy_state_->connections[conn_id]->buffer_write(data);
	} else { // call handler
		if(bindy_state_->m_datasink)
			bindy_state_->m_datasink(conn_id, data);
	}
}

void Bindy::callback_disc(conn_id_t conn_id) {
	if(bindy_state_->m_discnotify)
		bindy_state_->m_discnotify(conn_id);
}

in_addr Bindy::get_ip(conn_id_t conn_id) {
	tlock lock(bindy_state_->mutex);
	return bindy_state_->connections[conn_id]->get_ip();
}

void Bindy::initialize_network() {
	CryptoPP::Socket::StartSockets();
}

void Bindy::shutdown_network() {
	CryptoPP::Socket::ShutdownSockets();
}

//bool user_id_t::operator==(const user_id_t &other) const {
//	return std::memcmp(this->bytes, other.bytes, AUTH_DATA_LENGTH) == 0;
//}

}; // namespace bindy
