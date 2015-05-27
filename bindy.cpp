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
	std::map<conn_id_t, Connection*> connections;
	tthread::mutex mutex; // global mutex
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
		tlock(mutex);
		this->conn_id = id;
		if (map.count(conn_id) == 0) {
			map[conn_id] = 0;
		}
		map_prev[conn_id] = map[conn_id];
		++map[conn_id];
	}
	Countable(Countable const&) = delete;
	Countable& operator=(Countable const&) = delete;
	virtual ~Countable() {
		tlock(mutex);
		if (map.count(conn_id) == 1 && map[conn_id] > 1) {
			map_prev[conn_id] = map[conn_id];
			--map[conn_id];
		} else {
			map.erase(conn_id);
			map_prev.erase(conn_id);
		}
	}
	unsigned int count() {
		tlock(mutex);
		return map[conn_id];
	}
	unsigned int count_prev() {
		tlock(mutex);
		return map_prev[conn_id];
	}
private:
	conn_id_t conn_id;
	static std::map<conn_id_t, unsigned int> map;
	static std::map<conn_id_t, unsigned int> map_prev;
	static tthread::mutex mutex;
};
std::map<conn_id_t, unsigned int> Countable::map;
std::map<conn_id_t, unsigned int> Countable::map_prev;




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



class SharedStatus : public Countable {
public:
	SharedStatus(Connection *conn);
	~SharedStatus();

	void initial_exchange();
	void add_connection();
	void delete_connection();
	Message recv_packet();
	void callback_data(std::vector<uint8_t> data);

private:
	tthread::mutex mutex;
	Connection * conn;

};

/*!
* Class which contains information about a single connection.
*/
class Connection {
public:
	Connection(Bindy* bindy, Socket* _socket, conn_id_t conn_id, bool inits);
	~Connection();

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
	* Informs Bindy that this connection is established.
	*/
	void add_connection();

	/*!
	* Informs Bindy that this connection is being destroyed.
	*/
	void delete_connection();

	/*!
	* Sends callback data from thread to the Bindy class through the Connection class intermediary.
	*/
	void callback_data(std::vector<uint8_t> data);

	/*!
	* Returns connection identifier.
	*/
	conn_id_t id() {
		return conn_id;
	}

private:
	Connection(const Connection& other);
	Connection& operator=(const Connection& other);

	Bindy * bindy;
	Socket * sock;
	SharedStatus * status;
	CryptoPP::SecByteBlock send_key;
	CryptoPP::SecByteBlock recv_key;
	CryptoPP::SecByteBlock send_iv;
	CryptoPP::SecByteBlock recv_iv;
	tthread::mutex send_mutex;
	tthread::mutex recv_mutex;
	std::deque<uint8_t> * buffer;
	conn_id_t conn_id;
	bool inits_connect;

	void initial_exchange();
	in_addr get_ip();

	friend class Bindy;
	friend class SharedStatus;
	friend void socket_thread_function(void* arg);
};

SharedStatus::SharedStatus(Connection * conn) : Countable(conn->id())
{
	this->conn = conn;

	Socket *sock = conn->sock;
	CryptoPP::socket_t rawsock = sock->DetachSocket();

	struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	if (setsockopt(rawsock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
		throw "setsockopt failed";
	if (setsockopt(rawsock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
		throw "setsockopt failed";

	sock->AttachSocket(rawsock);
}

SharedStatus::~SharedStatus() 
{
}

void SharedStatus::initial_exchange()
{
	tlock(mutex);
	if (count() == 2) {
		conn->initial_exchange();
	}
}

void SharedStatus::add_connection()
{
	tlock(mutex);
	if (count() == 2) {
		conn->add_connection();
	}
}

void SharedStatus::delete_connection()
{
	tlock(mutex);
	if ( (count() == 1) && (count_prev() == 2) ) {
		conn->delete_connection();
	}
}

Message SharedStatus::recv_packet()
{
	tlock(mutex);
	if (count() == 2) {
		return conn->recv_packet();
	}
	else
		throw std::runtime_error("Connection is either not fully initialized or already half-dead");
}

void SharedStatus::callback_data(std::vector<uint8_t> data)
{
	tlock(mutex);
	if (count() == 2) {
		conn->callback_data(data);
	}
}

Connection::Connection(Bindy * _bindy, Socket *_socket, conn_id_t conn_id, bool _inits_connect) {
	this->inits_connect = _inits_connect;
	this->bindy = _bindy;
	this->sock = _socket;
	this->conn_id = conn_id;
	this->send_key = CryptoPP::SecByteBlock(AES::DEFAULT_KEYLENGTH);
	this->recv_key = CryptoPP::SecByteBlock(AES::DEFAULT_KEYLENGTH);
	this->send_iv = CryptoPP::SecByteBlock(AES::BLOCKSIZE);
	this->recv_iv = CryptoPP::SecByteBlock(AES::BLOCKSIZE);
	this->buffer = new std::deque<uint8_t>;
	this->status = nullptr;
}

Connection::~Connection() {
#ifdef _MSC_VER
	int how = SD_BOTH;
#else
	int how = SHUT_RDWR;
#endif
	sock->ShutDown(how);
	while (status->count() > 1) {
		sleep_ms(1);
	}
	delete status;

	sock->CloseSocket();
	delete sock;
	delete buffer;
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

	tlock lock(send_mutex);

	std::string plain_header, plain_body, cipher_header, cipher_body, cipher_all;

	plain_header = message->header_string();
	plain_body = message->data_string();

	CryptoPP::GCM< AES >::Encryption e;
	try {
		e.SetKeyWithIV(send_key, send_key.size(), send_iv, send_iv.size());
		StringSource(plain_header, true,
			new CryptoPP::AuthenticatedEncryptionFilter(e,
				new StringSink(cipher_header)
			) // StreamTransformationFilter
		); // StringSource
		send_iv.Assign(reinterpret_cast<const uint8_t*>(cipher_header.substr(cipher_header.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
		e.SetKeyWithIV(send_key, send_key.size(), send_iv, send_iv.size());
		StringSource(plain_body, true,
			new CryptoPP::AuthenticatedEncryptionFilter(e,
				new StringSink(cipher_body)
			) // StreamTransformationFilter
		); // StringSource
		send_iv.Assign(reinterpret_cast<const uint8_t*>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
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
	tlock lock(recv_mutex);
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

	d.SetKeyWithIV(recv_key, recv_key.size(), recv_iv, recv_iv.size());
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

	recv_iv.Assign(reinterpret_cast<const uint8_t*>(cipher_head.substr(cipher_head.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
	d.SetKeyWithIV(recv_key, recv_key.size(), recv_iv, recv_iv.size());
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
	recv_iv.Assign(reinterpret_cast<const uint8_t*>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);

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

void Connection::add_connection()
{
	bindy->add_connection(this->conn_id, this);
}

void Connection::callback_data(std::vector<uint8_t> data)
{
	bindy->callback_data(this->conn_id, data);
}

void Connection::delete_connection()
{
	bindy->disconnect(this->conn_id);
}

void Connection::initial_exchange()
{
	std::string remote_nodename;
	if (!inits_connect) { // this party accepts the connection
		// Initial exchange
		uint8_t username[USERNAME_LENGTH + 1];
		sock->Receive(username, USERNAME_LENGTH, 0);
		username[USERNAME_LENGTH] = '\0';

		// Authorization happens here
		std::string name((const char*)username);
		std::pair<bool, aes_key_t> pair = bindy->key_by_name(name);
		if (pair.first == false)
			throw std::runtime_error("key not found");
		aes_key_t key = pair.second;

		send_key.Assign(key.bytes, AES_KEY_LENGTH);
		recv_key.Assign(key.bytes, AES_KEY_LENGTH);

		sock->Receive(recv_iv.BytePtr(), AES::DEFAULT_KEYLENGTH, 0);
		send_iv.Assign(recv_iv);

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
		prng.GenerateBlock(send_iv, send_iv.size());
		recv_iv.Assign(send_iv);

		// Authorize ourselves here
		std::string name = bindy->get_master_login_username();
		std::pair<bool, aes_key_t> pair = bindy->key_by_name(name);
		if (pair.first == false)
			throw std::runtime_error("key not found");
		aes_key_t key = pair.second;

		send_key.Assign(key.bytes, AES_KEY_LENGTH);
		recv_key.Assign(key.bytes, AES_KEY_LENGTH);


		uint8_t username[USERNAME_LENGTH];
		std::string mname = bindy->get_master_login_username();
		memcpy(username, mname.c_str(), USERNAME_LENGTH);
		sock->Send(username, USERNAME_LENGTH, 0);
		sock->Send((const uint8_t*)(send_iv.BytePtr()), AES::DEFAULT_KEYLENGTH, 0);

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
	SharedStatus status((Connection*)arg);

	try {
		status.initial_exchange();

		// We are connected. Now update the list of connected nodes
		status.add_connection();

		// Connection established, now listen for messages and reply.
		while (true) { // actually: while m.packet_type != PacketLinkTermRequest
			Message m = status.recv_packet();

			//Process packet contents
			switch (m.packet_type()) {
				case link_pkt::PacketData: {
					status.callback_data(m.data_vector());
				} break;
				default: {
					DEBUG( "stf: unknown packet received, ignoring" );
				}; break; // ignore the unknown
			}
		}
	} catch (...) {
		DEBUG( "Caught exception, deleting connection..." );
		status.delete_connection();
	}
}

void Connection::init() {
	this->status = new SharedStatus(this);

	tthread::thread * t = new tthread::thread(socket_thread_function, this);
	t->detach();
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
		listen_sock.Create();
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

	int conn_id = conn_id_invalid;
	try {
		while (true) {
			Socket *sock = new Socket;
			sock->Create();
			listen_sock.Accept(*sock);

			conn_id++;
			try {
				// connection will add itself to bindy list after successfull initial exchange
				(new Connection(bindy, sock, conn_id, false))->init();
			}
			catch (...) {
				; /// failed connection attempt either due to key being rejected or ... ?
			}
		}
	} catch (std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
	}
	listen_sock.CloseSocket();
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
	: port_(12345), is_server_(is_server), is_buffered_(is_buffered)
{
	bindy_state_ = new BindyState();
	bindy_state_->m_datasink = nullptr;
	bindy_state_->m_discnotify = nullptr;
	bindy_state_->main_thread = nullptr;

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
	if (is_server_ && bindy_state_->main_thread != nullptr)
		bindy_state_->main_thread->join();
	delete bindy_state_->main_thread;
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
	if (is_server_ && bindy_state_->main_thread == nullptr) {
		bindy_state_->main_thread = new tthread::thread(main_thread_function, this);
	}
}

conn_id_t Bindy::connect (std::string addr) {
	Socket * sock = nullptr;
	Connection *c = nullptr;
	try {
		sock = new Socket();
		sock->Create();
		if (!sock->Connect(addr.c_str(), port_))
			throw std::runtime_error("Error establishing connection.");
	} catch (CryptoPP::Exception &e) {
		std::cerr << e.what() << std::endl;
		throw e;
	}
	conn_id_t conn_id = conn_id_invalid;
	{
		tlock lock(bindy_state_->mutex);
		do {
			conn_id = rand();
		} while (bindy_state_->connections.count(conn_id) != 0 || conn_id == conn_id_invalid);
		// id==0==conn_id_invalid is the single invalid state, so we don't return it
	}
	try {
		DEBUG( "creating connection ..." );
		(c = new Connection(this, sock, conn_id, true))->init();
	}
	catch (...) { // ?
		; // same as server listen thread
		DEBUG( "creating connection error" );
	}

	int sleep_count = 0, sleep_time = 1;
	while (bindy_state_->connections.count(conn_id) == 0 /* && sleep_time*sleep_count < timeout */) {
		sleep_ms(sleep_time);
		sleep_count++;
	}
	if (bindy_state_->connections.count(conn_id) == 0) {
		delete c;
		return conn_id_invalid;
	}
	DEBUG( "waited " << sleep_count << " * " << sleep_time << "ms intervals to connect" );
	return conn_id;
}

void Bindy::send_data (conn_id_t conn_id, std::vector<uint8_t> data) {
	Message message(data.size(), link_pkt::PacketData, reinterpret_cast<const char*>( &data.at(0) ));

	if (bindy_state_->connections.count(conn_id) == 1) { // should be 1 exactly...
		tlock lock(bindy_state_->mutex);
		Connection * conn = bindy_state_->connections[conn_id];
		DEBUG( "sending " << data.size() << " raw bytes..." );
		DEBUG( "bytes =  " << hex_encode(data) );
		conn->send_packet(&message);
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

void Bindy::add_connection(conn_id_t conn_id, Connection * conn) {
	tlock lock(bindy_state_->mutex);
	bindy_state_->connections[conn_id] = conn;
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
	std::map<conn_id_t,Connection*>::iterator it;
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
