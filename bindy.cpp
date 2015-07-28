/// @file
/// @mainpage Bindy API Reference
///
/// @section intro_sec Introduction
/// Bindy synopsis
///


#include "bindy.h"

#include <cryptlib.h>
#include <osrng.h>
#include <hex.h>
#include <filters.h>
#include <gcm.h>
#include <secblock.h>
#include <socketft.h>
#include <aes.h>

#include "tinythread.h"

#include <fstream>
#include <stdexcept>
#include <atomic>

using CryptoPP::StringSink;
using CryptoPP::StringSource;
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


namespace bindy
{
static tthread::mutex * stdout_mutex = new tthread::mutex();

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
void sleep_ms(size_t ms)
{
#if defined(WIN32) || defined(WIN64)
	Sleep((DWORD)ms);
#else
	usleep(1000 * ms);
#endif
}

/*! Lock guard short type definition. */
typedef tthread::lock_guard<tthread::mutex> tlock;

/* Broadcast data struct definition */
typedef struct bcast_data_t {
	std::vector<uint8_t> data;
	std::string addr;
} bcast_data_t;

/*! This function takes a pointer to an array of chars and its size and returns its representation in hex as a string. */
std::string hex_encode(const char* s, size_t size) {
	std::string encoded;
	StringSource(reinterpret_cast<const uint8_t*>(s), size, true,
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
	return hex_encode((const char*)&v[0], v.size());
}

/*! Helper function for CryptoPP encode/decode functions which require an std::string as parameter. Copies characters into the string. */
void string_set(std::string *str, char* buf, int size) {
	str->resize(size);
	for (int i = 0; i<size; i++) {
		str->at(i) = buf[i];
	}
}

void string_set(std::string *str, uint8_t* buf, int size) {
	string_set(str, reinterpret_cast<char*>(buf), size);
}

class BindyState
{
public:
	void (* m_datasink)(conn_id_t conn_id, std::vector<uint8_t> data);
	void (* m_discnotify)(conn_id_t conn_id);

	std::map<std::string, aes_key_t> login_key_map;
	tthread::thread * main_thread;
	tthread::thread * bcast_thread;
	std::map<conn_id_t, SuperConnection*> connections;
	tthread::mutex mutex; // global mutex
	tthread::mutex interlock_mutex; // mutex to sync betweern listening TCP and UDP threads
	std::string nodename; // name of this node
	login_pair_t master_login; // root key

	BindyState() { }
	~BindyState() { }

private:
	BindyState(const BindyState&) = delete;
	BindyState& operator=(const BindyState&) = delete;
};

class Countable
{
public:
	Countable(conn_id_t id)	{
		tlock(global_mutex);
		this->conn_id = id;
		if (map.count(conn_id) == 0) {
			map[conn_id] = 0;
		}
		map_prev[conn_id] = map[conn_id];
		++map[conn_id];
		mutexes[conn_id] = new tthread::mutex();
	}
	Countable(Countable const&) = delete;
	Countable& operator=(Countable const&) = delete;
	virtual ~Countable() {
		tlock(global_mutex);
		if (map.count(conn_id) == 1 && map[conn_id] > 1) {
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
		tlock(global_mutex);
		return map[conn_id];
	}
	unsigned int count_prev() {
		tlock(global_mutex);
		return map_prev[conn_id];
	}
	tthread::mutex* mutex() {
		return mutexes[conn_id];
	}
private:
	conn_id_t conn_id;
	static std::map<conn_id_t, unsigned int> map;
	static std::map<conn_id_t, unsigned int> map_prev;
	static std::map<conn_id_t, tthread::mutex*> mutexes;
	static tthread::mutex global_mutex;
};
std::map<conn_id_t, unsigned int> Countable::map;
std::map<conn_id_t, unsigned int> Countable::map_prev;
std::map<conn_id_t, tthread::mutex*> Countable::mutexes;
tthread::mutex Countable::global_mutex;

int conn_id = conn_id_invalid; // used in tcp- and udp-listen thread functions


/*!
* A helper class which contains a single message to be encrypted and sent over the TCP socket.
*/
class Message {
public:
	Message(size_t data_length, link_pkt packet_type, const char* ptr);
	Message(header_t header, const char* ptr);
	Message(const Message& other);
	~Message();

	std::string header_string();
	std::string data_string();
	std::vector<uint8_t> data_vector();
	link_pkt packet_type();

private:
	header_t header;
	uint8_t * p_body;
};



/*!
* Class which contains information about a single connection.
*/
class Connection : public Countable {
public:
	Connection(Bindy* bindy, Socket* _socket, conn_id_t conn_id, bool inits);
	~Connection();
	Connection(Connection* other);
	/*!
	* Initializes shared socket.
	*/
	void init();

	/*!
	* Encrypts and sends a single message into this connection.
	*/
	void send_packet(Message * m);

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
	int buffer_read(uint8_t * p, int size);

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
	Connection(const Connection& other);
	Connection& operator=(const Connection& other);

	Bindy * bindy;
	Socket * sock;
	CryptoPP::SecByteBlock * send_key;
	CryptoPP::SecByteBlock * recv_key;
	CryptoPP::SecByteBlock * send_iv;
	CryptoPP::SecByteBlock * recv_iv;
	tthread::mutex *send_mutex;
	tthread::mutex *recv_mutex;
	std::deque<uint8_t> * buffer;
	conn_id_t conn_id;
	bool inits_connect;

	in_addr get_ip();

	friend class Bindy;
	friend void socket_thread_function(void* arg);
};

void socket_thread_function(void* arg);
class SuperConnection : public Connection {
public:
	SuperConnection(Bindy* bindy, Socket* _socket, conn_id_t conn_id, bool inits, bcast_data_t bcast_data);
	~SuperConnection();
};

SuperConnection::SuperConnection(Bindy * _bindy, Socket *_socket, conn_id_t conn_id, bool _inits_connect, bcast_data_t bcast_data)
 : Connection(_bindy, _socket, conn_id, _inits_connect)
{
	initial_exchange(bcast_data);
	tthread::thread * t = new tthread::thread(socket_thread_function, this);
	t->detach();
}

SuperConnection::~SuperConnection() {
}

Connection::Connection(Bindy * _bindy, Socket *_socket, conn_id_t conn_id, bool _inits_connect) : Countable(conn_id) {
	if (count() == 1) {
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
		this->buffer = new std::deque<uint8_t>;
	}
}

Connection::Connection(Connection* other) : Countable(other->conn_id) {
	if (count() > 1) {
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
		this->buffer = other->buffer;
	}
}

Connection::~Connection() {
	tlock(*mutex());
	if (count() == 2) {
		int how;
#ifdef _MSC_VER
		how = SD_BOTH;
#else
		how = SHUT_RDWR;
#endif
		if (sock) {
			try {
				sock->ShutDown(how);
			}
			catch (CryptoPP::Socket::Err &e) {
				DEBUG("Socket shutdown failed for reason " << e.what() << ". Likely the other side closed connection first.");
			}
		}
	}
	else if (count() == 1) {
		if (sock) {
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
	}
}

Message::Message(size_t data_length, link_pkt packet_type, const char* ptr) {
	assert(data_length + sizeof(header_t) <= UINT_MAX);
	this->header.data_length = static_cast<uint32_t>(data_length);
	this->header.packet_type = packet_type;

	p_body = new uint8_t[header.data_length];
	if (header.data_length > 0)
		memcpy(this->p_body, ptr, header.data_length);
}

Message::Message(header_t header, const char* ptr) {
	this->header = header;

	p_body = new uint8_t[header.data_length];
	if (header.data_length > 0)
		memcpy(this->p_body, ptr, header.data_length);
}

Message::Message(const Message& other) : header(other.header), p_body(new uint8_t[other.header.data_length]) {
	if (header.data_length > 0)
		memcpy(this->p_body, other.p_body, header.data_length);
}

Message::~Message() {
	delete[] p_body;
}

std::string Message::header_string() {
	std::string ret;
	ret.resize( sizeof(header_t) );
	ret.assign( reinterpret_cast<const char*>(&header), ret.size() );
	return ret;
}

std::string Message::data_string() {
	std::string ret;
	ret.resize( header.data_length );
	ret.assign( reinterpret_cast<const char*>(p_body), ret.size() );
	return ret;
}

std::vector<uint8_t> Message::data_vector() {
	std::vector<uint8_t> v(header.data_length);
	memcpy(&v.at(0), p_body, v.size());
	return v;
}

link_pkt Message::packet_type() {
	return header.packet_type;
}

// Sends "message" data into the connection. Modifies connection IV in preparation for the next packet.
void Connection::send_packet(Message * message) {

	tlock lock(*send_mutex);

	std::string plain_header, plain_body, cipher_header, cipher_body, cipher_all;

	plain_header = message->header_string();
	plain_body = message->data_string();

	CryptoPP::GCM< AES >::Encryption e;
	try {
		e.SetKeyWithIV(*send_key, send_key->size(), *send_iv, send_iv->size());
		StringSource(plain_header, true,
			new CryptoPP::AuthenticatedEncryptionFilter(e,
				new StringSink(cipher_header)
			) // StreamTransformationFilter
		); // StringSource
		send_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_header.substr(cipher_header.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
		e.SetKeyWithIV(*send_key, send_key->size(), *send_iv, send_iv->size());
		StringSource(plain_body, true,
			new CryptoPP::AuthenticatedEncryptionFilter(e,
				new StringSink(cipher_body)
			) // StreamTransformationFilter
		); // StringSource
		send_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
	} catch (CryptoPP::Exception &e) {
		std::cerr << "Caught exception (encryption): " << e.what() << std::endl;
		throw e;
	}

	cipher_all.append(cipher_header);
	cipher_all.append(cipher_body);
	int sent = 0;
	size_t to_send = cipher_all.length();

	try {
		sent = sock->Send(reinterpret_cast<const uint8_t*>(cipher_all.data()), to_send, 0);
		DEBUG( "to send (w/headers): " << to_send << "; sent = " << sent );
	} catch (CryptoPP::Exception &e) {
		std::cerr << "Caught exception (net): " << e.what() << std::endl;
		throw e;
	}
}

// Receives message from connection. Modifies connection IV in preparation for the next packet.
Message Connection::recv_packet() {
	tlock lock(*recv_mutex);
	int get, rcv;
	CryptoPP::GCM< AES >::Decryption d;

	// header data recv
	const int head_enc_size = (sizeof (header_t)) +  AES::BLOCKSIZE;
	get = 0;
	rcv = 0;
	unsigned char buf_head[ head_enc_size ];
	memset(buf_head, 0, head_enc_size);

	do {
		get = sock->Receive(&buf_head[rcv], head_enc_size - rcv, 0);
		if (get == 0) { // The other side closed the connection
			throw std::runtime_error("Error receiving packet.");
		}
		rcv += get;
	} while (head_enc_size - rcv > 0);

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
	catch(const CryptoPP::Exception& e) {
		std::cerr << "Caught exception (decryption): " << e.what() << std::endl;
		throw e;
	}
	header_t header;
	memcpy(&header, recovered_head.c_str(), (sizeof (header_t)));

	// body data recv
	int body_enc_size = header.data_length + AES::BLOCKSIZE;
	get = 0;
	rcv = 0;
	uint8_t * p_body = new uint8_t[header.data_length + CryptoPP::AES::BLOCKSIZE];
	do {
		get = sock->Receive(p_body+rcv, body_enc_size-rcv, 0);
		if (get == 0) { // The other side closed the connection
			delete[] p_body;
			throw std::runtime_error("Error receiving packet.");
		}
		rcv += get;
	} while (body_enc_size-rcv > 0);

	// body decrypt
	std::string cipher_body, recovered_body;
	string_set(&cipher_body, p_body, rcv);
	delete[] p_body;

	recv_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_head.substr(cipher_head.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
	d.SetKeyWithIV(*recv_key, recv_key->size(), *recv_iv, recv_iv->size());
	try {
		StringSource s(cipher_body, true,
			new CryptoPP::AuthenticatedDecryptionFilter(d,
				new StringSink(recovered_body)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e) {
		std::cerr << "Caught exception (decryption): " << e.what() << std::endl;
		throw e;
	}
	recv_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);

	assert(header.data_length == recovered_body.length());
	Message message(header, recovered_body.c_str());
	return message;
}

unsigned int Connection::buffer_size()
{
	return buffer->size();
}

int Connection::buffer_read(uint8_t * p, int size)
{
	int i = 0;
	while (i < size && !buffer->empty()) {
		*(p + i) = buffer->front();
		buffer->pop_front();
		i++;
	}
	return i;
}

void Connection::buffer_write(std::vector<uint8_t> data)
{
	for (unsigned int i = 0; i<data.size(); ++i)
		buffer->push_back(data.at(i));
}

void Connection::callback_data(std::vector<uint8_t> data)
{
	bindy->callback_data(this->conn_id, data);
}

void Connection::initial_exchange(bcast_data_t bcast_data)
{
	std::string remote_nodename;

	bool use_bcast = (sock == nullptr);

	if (!inits_connect) { // this party accepts the connection
		// Initial exchange
		uint8_t username[USERNAME_LENGTH + 1];
		memset(username, 0, sizeof(username));
		if (use_bcast) {
			memcpy(username, reinterpret_cast<const void*>(&bcast_data.data.at(0)), USERNAME_LENGTH);
		}
		else {
			sock->Receive(username, USERNAME_LENGTH, 0);
		}
		username[USERNAME_LENGTH] = '\0';

		// Authorization happens here
		std::string name((const char*)username);
		std::pair<bool, aes_key_t> pair = bindy->key_by_name(name);
		if (pair.first == false) {
			throw std::runtime_error("key not found");
		}
		aes_key_t key = pair.second;

		send_key->Assign(key.bytes, AES_KEY_LENGTH);
		recv_key->Assign(key.bytes, AES_KEY_LENGTH);

		if (use_bcast) {
			memcpy(recv_iv->BytePtr(), reinterpret_cast<const void*>(&bcast_data.data.at(USERNAME_LENGTH)), AES_KEY_LENGTH);
		}
		else {
			sock->Receive(recv_iv->BytePtr(), AES_KEY_LENGTH, 0);
		}
		send_iv->Assign(*recv_iv);

		// The tcp socket is still null, connect it first
		if (use_bcast) {
			sock = new Socket();
			sock->Create(SOCK_STREAM);
			DEBUG("Connecting to " << bcast_data.addr);
			if (!sock->Connect(bcast_data.addr.c_str(), bindy->port())) {
				DEBUG("Connect fail");
			}
			else {
				DEBUG("Connect ok");
			}
		}

		Message m_recv1 = recv_packet();
		remote_nodename = m_recv1.data_string();

		std::string nodename = bindy->get_nodename();
		Message m_send1(nodename.length(), link_pkt::PacketInitReply, nodename.c_str());
		send_packet(&m_send1);

		Message m_recv2 = recv_packet();

		Message m_send2(0, link_pkt::PacketLinkInfo, NULL);
		send_packet(&m_send2);
	}
	else { // this party initiates the connection
		CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock(*send_iv, send_iv->size());
		recv_iv->Assign(*send_iv);

		// Authorize ourselves here
		std::string name = bindy->get_master_login_username();
		std::pair<bool, aes_key_t> pair = bindy->key_by_name(name);
		if (pair.first == false)
			throw std::runtime_error("key not found");
		aes_key_t key = pair.second;

		send_key->Assign(key.bytes, AES_KEY_LENGTH);
		recv_key->Assign(key.bytes, AES_KEY_LENGTH);


		uint8_t username[USERNAME_LENGTH];
		std::string mname = bindy->get_master_login_username();
		memcpy(username, mname.c_str(), USERNAME_LENGTH);
		if (use_bcast) {
			uint8_t bc_packet[USERNAME_LENGTH + AES_KEY_LENGTH];
			memcpy(bc_packet, username, USERNAME_LENGTH);
			memcpy(bc_packet + USERNAME_LENGTH, send_iv->BytePtr(), AES_KEY_LENGTH);
			// accept incoming connection(s?) from server(s?) who will hear our broadcast and want to talk back
			Socket listen_sock;
			listen_sock.Create(SOCK_STREAM);
			listen_sock.Bind(bindy->port_,NULL);
			listen_sock.Listen();

			// send a broadcast itself
			Socket bcast_sock;
			bcast_sock.Create(SOCK_DGRAM);
			std::string addr("255.255.255.255"); // todo check: does this properly route on lin & win?
			if (!bcast_sock.Connect(addr.c_str(), bindy->port_)) {
				throw std::runtime_error("Error establishing connection.");
			}
			bcast_sock.Send(bc_packet, sizeof(bc_packet), 0);

			// wait for reply
			timeval t;
			t.tv_sec = 5;
			t.tv_usec = 0;
			if (listen_sock.ReceiveReady(&t)) {
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
			sock->Send(username, USERNAME_LENGTH, 0);
			sock->Send((const uint8_t*)(send_iv->BytePtr()), AES_KEY_LENGTH, 0);
		}

		std::string nodename = bindy->get_nodename();
		Message m_send1(nodename.length(), link_pkt::PacketInitRequest, nodename.c_str());
		send_packet(&m_send1);

		Message m_recv1 = recv_packet();
		remote_nodename = m_recv1.data_string();

		Message m_send2(0, link_pkt::PacketLinkInfo, NULL);
		send_packet(&m_send2);

		Message m_recv2 = recv_packet();
	}
}

in_addr Connection::get_ip() {
	in_addr ip;
	sockaddr psa;
	CryptoPP::socklen_t psaLen = sizeof (psa);

	sock->GetPeerName(&psa, &psaLen);
	if (psa.sa_family == AF_INET)
		ip = ((sockaddr_in*)&psa)->sin_addr;
	else
		ip.s_addr = INADDR_NONE;
	return ip;
}

void socket_thread_function(void* arg) {
	Connection* conn = nullptr;
	try {
		conn = new Connection((Connection*)arg);
		while (true) { // actually: while m.packet_type != PacketLinkTermRequest
			Message m = conn->recv_packet();

			//Process packet contents
			switch (m.packet_type()) {
				case link_pkt::PacketData: {
					conn->callback_data(m.data_vector());
				} break;
				default: {
					DEBUG( "stf: unknown packet received, ignoring" );
				}; break; // ignore the unknown
			}
		}
	} catch (...) {
		DEBUG( "Caught exception, deleting connection..." );
	}
	delete conn;
}


bool set_socket_options (Socket *s) {
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

	ok &= ( 0 == setsockopt(*s, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int)) );
	// TODO non-portable line of code
#ifdef __linux__
	ok &= ( 0 == setsockopt(*s, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(int)) );
	ok &= ( 0 == setsockopt(*s, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle, sizeof(int)) );
	ok &= ( 0 == setsockopt(*s, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_cnt, sizeof(int)) );
#endif

	// Also disable Nagle, because we want faster response and each Bindy packet is a complete packet that should be wrapped in TCP and sent right away
	optval = 1;
	ok &= ( 0 == setsockopt(*s, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(int)) );
#endif
	return ok;
}

void main_thread_function(void *arg) {
	Bindy* bindy = (Bindy*)arg;

	Socket listen_sock;
	try {
		DEBUG("Creating TCP listen socket...");
		listen_sock.Create(SOCK_STREAM);
		listen_sock.Bind(bindy->port(), NULL);
	} catch (std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
		throw e;
	}
	if (!set_socket_options(&listen_sock))  { // all connection sockets inherit required options from listening socket
		std::cerr << "Could not set socket options." << std::endl;
		throw std::runtime_error("setsockopt failed");
	}
	listen_sock.Listen();

	try {
		while (true) {
			Socket *sock = new Socket;
			sock->Create(SOCK_STREAM);
			listen_sock.Accept(*sock);

			conn_id_t local_conn_id;
			{
				tlock(bindy->bindy_state_->interlock_mutex);
				local_conn_id = conn_id;
				conn_id++;
			}

			try {
				bcast_data_t empty;
				empty.addr = std::string();
				empty.data = std::vector<uint8_t>();
				SuperConnection *sc = new SuperConnection(bindy, sock, local_conn_id, false, empty);
				bindy->add_connection(local_conn_id, sc);
			}
			catch (...) {
				DEBUG("Error creating and/or initializing connection in main_thread");
				; /// failed connection attempt either due to key being rejected or ... ?
			}
		}
	} catch (std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
	}
	listen_sock.CloseSocket();
}

void broadcast_thread_function(void *arg) {
	Bindy* bindy = (Bindy*)arg;

	Socket bcast_sock;
	try {
		DEBUG( "Creating UDP listen socket..." );
		bcast_sock.Create(SOCK_DGRAM);
		bcast_sock.Bind(bindy->port(), NULL);
	} catch (std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
		throw e;
	}

	bool recv_ok = true;
	try {
		while (recv_ok) {
			char setuprq[USERNAME_LENGTH + AES_KEY_LENGTH];
			//unsigned int size = bcast_sock.Receive(setuprq, sizeof (setuprq), NULL);
			// Cannot use Cryptopp wrapper here because it doesn't provide src addr for broadcasts
			struct sockaddr from;
			socklen_t fromlen = sizeof(from);
			unsigned int size = recvfrom(bcast_sock, setuprq, sizeof(setuprq), 0, &from, &fromlen);
			struct sockaddr_in from_in = *(sockaddr_in*)&from;
			std::string addrbuf;
			if (from.sa_family == AF_INET) {
				addrbuf = inet_ntoa(from_in.sin_addr);
				DEBUG("received broadcast from " << addrbuf << ", size = " << size);
			}
			else {
				DEBUG("unknown address family");
				break;
			}

			conn_id_t local_conn_id;
			{
				tlock(bindy->bindy_state_->interlock_mutex);
				local_conn_id = conn_id;
				conn_id++;
			}

			try {
				bcast_data_t not_empty;
				not_empty.addr = addrbuf;
				not_empty.data = std::vector<uint8_t>(setuprq, setuprq+size);
				SuperConnection *sc = new SuperConnection(bindy, nullptr, local_conn_id, false, not_empty);
				bindy->add_connection(local_conn_id, sc);
			}
			catch (...) {
				DEBUG("Error creating and/or initializing connection in broadcast_thread");
				; /// failed connection attempt either due to key being rejected or ... ?
			}
		}
	} catch (std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
	}
	bcast_sock.CloseSocket();
}

std::pair<bool, aes_key_t> Bindy::key_by_name(std::string name) {
	std::pair<bool, aes_key_t> result;
	if (bindy_state_->login_key_map.count(name) == 1) {
		result.first = true;
		result.second = bindy_state_->login_key_map[name];
	}
	else {
		result.first = false;
	}
	return result;
}



Bindy::Bindy(std::string filename, bool is_server, bool is_buffered)
	: port_(49150), is_server_(is_server), is_buffered_(is_buffered)
{
	bindy_state_ = new BindyState();
	bindy_state_->m_datasink = nullptr;
	bindy_state_->m_discnotify = nullptr;
	bindy_state_->main_thread = nullptr;
	bindy_state_->bcast_thread = nullptr;

	if (AES_KEY_LENGTH != CryptoPP::AES::DEFAULT_KEYLENGTH)
		throw std::logic_error("AES misconfiguration, expected AES-128");

	std::ifstream is (filename.data(), std::ifstream::binary);
	if (is) {
		is.seekg (0, is.end);
		//std::streampos length = is.tellg();
		is.seekg (0, is.beg);
	} else {
		throw std::runtime_error("Error opening file");
	}
	login_pair_t login;
	int count = 0;
	while (is) {
		is.read ((char*)&login, sizeof(login_pair_t));
		if (is.gcount() == sizeof(login_pair_t)) {
			if (count == 0) { // the first key becomes our root
				bindy_state_->master_login = login;
			}
			bindy_state_->login_key_map[login.username] = login.key;
		}
		else
			break;
		count++;
	}
	is.close();
};

Bindy::~Bindy() {
	if (is_server_) {
		if (bindy_state_->main_thread != nullptr)
			bindy_state_->main_thread->join();
		if (bindy_state_->bcast_thread != nullptr)
			bindy_state_->bcast_thread->join();
	}
	delete bindy_state_->main_thread;
	delete bindy_state_->bcast_thread;
	delete bindy_state_;
};

void Bindy::set_handler (void (* datasink)(conn_id_t conn_id, std::vector<uint8_t> data)) {
	if (!is_buffered_)
		bindy_state_->m_datasink = datasink;
}

void Bindy::set_discnotify(void (* discnotify)(conn_id_t) ) {
	if (!is_buffered_)
		bindy_state_->m_discnotify = discnotify;
}

/*!

*/
void Bindy::connect () {
	tlock lock(bindy_state_->mutex);
	if (is_server_) {
		if (bindy_state_->main_thread == nullptr) {
			bindy_state_->main_thread = new tthread::thread(main_thread_function, this);
		}
		if (bindy_state_->bcast_thread == nullptr) {
			bindy_state_->bcast_thread = new tthread::thread(broadcast_thread_function, this);
		}
	}
}

conn_id_t Bindy::connect (std::string addr) {
	Socket * sock = nullptr;
	SuperConnection *sc = nullptr;
	if (addr.empty()) { // use broadcast to connect somewhere
		tlock lock(bindy_state_->mutex);
		do {
			conn_id = rand();
		} while (bindy_state_->connections.count(conn_id) != 0 || conn_id == conn_id_invalid);
		// id==0==conn_id_invalid is the single invalid state, so we don't return it
		try {
			DEBUG( "creating connection for udp init..." );
			bcast_data_t empty;
			empty.addr = std::string();
			empty.data = std::vector<uint8_t>();
			sc = new SuperConnection(this, nullptr, conn_id, true, empty);
			bindy_state_->connections[conn_id] = sc;
		}
		catch (...) { // ?
			; // same as server listen thread
			DEBUG( "Error creating and/or initializing connection in connect() over udp" );
			return conn_id_invalid;
		}
	} else { // try to connect to the specified host
		try {
			DEBUG("using tcp to connect to " << addr);
			sock = new Socket();
			sock->Create(SOCK_STREAM);
			if (!sock->Connect(addr.c_str(), port_))
				throw std::runtime_error("Error establishing connection.");
		} catch (CryptoPP::Exception &e) {
			std::cerr << e.what() << std::endl;
			throw e;
		}

		{
			tlock lock(bindy_state_->mutex);
			do {
				conn_id = rand();
			} while (bindy_state_->connections.count(conn_id) != 0 || conn_id == conn_id_invalid);
			// id==0==conn_id_invalid is the single invalid state, so we don't return it
			try {
				DEBUG( "creating connection for tcp init..." );
				bcast_data_t empty;
				empty.addr = std::string();
				empty.data = std::vector<uint8_t>();
				sc = new SuperConnection(this, sock, conn_id, true, empty);
				bindy_state_->connections[conn_id] = sc;
			}
			catch (...) { // ?
				; // same as server listen thread
				DEBUG( "Error creating and/or initializing connection in connect() over tcp" );
				return conn_id_invalid;
			}
		}
	}
	return conn_id;
}

void Bindy::send_data (conn_id_t conn_id, std::vector<uint8_t> data) {
	Message message(data.size(), link_pkt::PacketData, reinterpret_cast<const char*>( &data.at(0) ));

	if (bindy_state_->connections.count(conn_id) == 1) { // should be 1 exactly...
		tlock lock(bindy_state_->mutex);
		SuperConnection * sconn = bindy_state_->connections[conn_id];
		DEBUG( "sending " << data.size() << " raw bytes..." );
		DEBUG( "bytes =  " << hex_encode(data) );
		sconn->send_packet(&message);
		DEBUG( "data sent" );
	} else {
		throw std::runtime_error("Error in send_data");
	}
}

int Bindy::read(conn_id_t conn_id, uint8_t * p, int size) {
	tlock lock(bindy_state_->mutex);
	if (bindy_state_->connections.count(conn_id) == 1) {
		return bindy_state_->connections[conn_id]->buffer_read(p, size);
	}
	return -1;
}

int Bindy::get_data_size (conn_id_t conn_id) {
	tlock lock(bindy_state_->mutex);
	if (bindy_state_->connections.count(conn_id) == 1) {
		return static_cast<int>(bindy_state_->connections[conn_id]->buffer_size());
	}
	return -1;
}

std::string Bindy::get_master_login_username () {
	if (bindy_state_->login_key_map.size() == 0) {
		throw std::runtime_error("Error in get_master_login_username");
	}
	return bindy_state_->master_login.username;
}

void Bindy::set_nodename (std::string nodename)
{
	bindy_state_->nodename = nodename;
}

std::string Bindy::get_nodename (void)
{
	return bindy_state_->nodename;
}

bool Bindy::is_server()
{
	return is_server_;
}

int Bindy::port()
{
	return port_;
}

void Bindy::add_connection(conn_id_t conn_id, SuperConnection * sconn) {
	tlock lock(bindy_state_->mutex);
	bindy_state_->connections[conn_id] = sconn;
}

void Bindy::delete_connection(conn_id_t conn_id) {
	tlock lock(bindy_state_->mutex);
	if (bindy_state_->connections.count(conn_id) == 1) {
		delete bindy_state_->connections[conn_id]; // safe, because we're under the global bindy mutex
		bindy_state_->connections.erase(conn_id);
	}
}

std::list<conn_id_t> Bindy::list_connections () {
	tlock lock(bindy_state_->mutex);
	std::list<conn_id_t> list;
	std::map<conn_id_t,SuperConnection*>::iterator it;
	for (it = bindy_state_->connections.begin(); it != bindy_state_->connections.end(); ++it) {
		list.push_back(it->first);
	}
	return list;
}

void Bindy::disconnect (conn_id_t conn_id) {
	delete_connection(conn_id);
	callback_disc(conn_id);
}

void Bindy::callback_data (conn_id_t conn_id, std::vector<uint8_t> data) {
	if (is_buffered_) { // save to buffer
		tlock lock(bindy_state_->mutex);
		if (bindy_state_->connections.count(conn_id) == 1)
			bindy_state_->connections[conn_id]->buffer_write(data);
	} else { // call handler
		if (bindy_state_->m_datasink)
			bindy_state_->m_datasink(conn_id, data);
	}
}

void Bindy::callback_disc (conn_id_t conn_id) {
	if (bindy_state_->m_discnotify)
		bindy_state_->m_discnotify(conn_id);
}

in_addr Bindy::get_ip(conn_id_t conn_id) {
	tlock lock(bindy_state_->mutex);
	return bindy_state_->connections[conn_id]->get_ip();
}

void Bindy::initialize_network()
{
	CryptoPP::Socket::StartSockets();
}

void Bindy::shutdown_network()
{
	CryptoPP::Socket::ShutdownSockets();
}

}; // namespace bindy
