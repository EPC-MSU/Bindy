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

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Exception;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::GCM;
using CryptoPP::AES;
using CryptoPP::SecByteBlock;
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
#define DEBUG(text) { ; }
//#define DEBUG(text) { stdout_mutex->lock(); cout << text << std::endl; stdout_mutex->unlock(); }

// TCP keepalive options used on socket
#define KEEPINTVL 5
#define KEEPIDLE 10
#define KEEPCNT 3

// common sleep function (conditional define (urgh))
#if defined(WIN32) || defined(WIN64)
void sleep_ms(size_t ms)
{
	Sleep((DWORD)ms);
}
#else
void sleep_ms(size_t ms)
{
	usleep(1000 * ms);
}
#endif

typedef tthread::lock_guard<tthread::mutex> tlock;

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
	void assign_key_by_name(std::string name, SecByteBlock *key);
private:
	BindyState(const BindyState&) = delete;
	BindyState& operator=(const BindyState&) = delete;
};

typedef struct {
	Bindy * class_ptr;
	Socket * sock_ptr;
	bool inits_connect;
	bool connect_ok;
	conn_id_t conn_id;
	bool is_buffered;
} thread_param_t;

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
	std::deque<uint8_t> * buffer;
};


Connection::Connection() {
	this->sock = new Socket();
	this->send_key = new SecByteBlock(AES::DEFAULT_KEYLENGTH);
	this->recv_key = new SecByteBlock(AES::DEFAULT_KEYLENGTH);
	this->send_iv = new SecByteBlock(AES::BLOCKSIZE);
	this->recv_iv = new SecByteBlock(AES::BLOCKSIZE);
	this->send_mutex = new tthread::mutex();
	this->recv_mutex = new tthread::mutex();
	this->buffer = new /*spm::circular_buffer<uint8_t>;*/ std::deque<uint8_t>;
//	this->buffer->reserve(1024); // todo parametrize
}

Connection::~Connection() {
	sock->CloseSocket();
	delete sock;
	delete send_key;
	delete recv_key;
	delete send_iv;
	delete recv_iv;
	delete send_mutex;
	delete recv_mutex;
	delete buffer;
}





Message::Message(size_t packet_length, link_pkt packet_type) {
	assert(packet_length <= UINT_MAX);
	this->header.packet_length = static_cast<uint32_t>(packet_length);
	this->header.packet_type = packet_type;
	p_body = new uint8_t[header.packet_length];
}

Message::Message(header_t header) {
	this->header = header;
	p_body = new uint8_t[header.packet_length];
}

Message::Message(const Message& other) : header(other.header), p_body(new uint8_t[other.header.packet_length]) {
	memcpy(this->p_body, other.p_body, header.packet_length);
}

Message::~Message() {
	delete[] p_body;
}


std::string hex_encode(const char* s, size_t size) {
	std::string encoded;
	StringSource(reinterpret_cast<const uint8_t*>(s), size, true,
		new HexEncoder(
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

void string_set(std::string *str, char* buf, int size) {
	str->resize(size);
	for (int i=0; i<size; i++) {
		str->at(i) = buf[i];
	}
}

void string_set(std::string *str, uint8_t* buf, int size) {
	string_set(str, reinterpret_cast<char*>(buf), size);
}

// Sends "message" data into the connection "conn". Modifies its IV in preparation for the next packet.
void send_packet(Connection * conn, Message * message) {

	tlock lock(*(conn->send_mutex));

	std::string plain_header, plain_body, cipher_header, cipher_body, cipher_all;

	string_set(&plain_header, reinterpret_cast<uint8_t*>(&message->header), sizeof(header_t));
	string_set(&plain_body, message->p_body, message->header.packet_length);

	GCM< AES >::Encryption e;
	try {
		e.SetKeyWithIV(*conn->send_key, conn->send_key->size(), *conn->send_iv, conn->send_iv->size());
		StringSource(plain_header, true,
			new AuthenticatedEncryptionFilter(e,
				new StringSink(cipher_header)
			) // StreamTransformationFilter
		); // StringSource
		conn->send_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_header.substr(cipher_header.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
		e.SetKeyWithIV(*conn->send_key, conn->send_key->size(), *conn->send_iv, conn->send_iv->size());
		StringSource(plain_body, true,
			new AuthenticatedEncryptionFilter(e,
				new StringSink(cipher_body)
			) // StreamTransformationFilter
		); // StringSource
		conn->send_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
	} catch (CryptoPP::Exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
	}

	cipher_all.append(cipher_header);
	cipher_all.append(cipher_body);
	int sent = 0;
	size_t to_send = cipher_all.length();

	try {
		sent = conn->sock->Send(reinterpret_cast<const uint8_t*>(cipher_all.data()), to_send, 0);
		DEBUG( "BINDY> to send (w/headers): " << to_send << "; sent = " << sent );
	} catch (CryptoPP::Exception &e) {
		std::cerr << "Exception. " << e.what() << std::endl;
	}
}

// Receives message from connection "conn". Modifies its IV in preparation for the next packet.
Message recv_packet(Connection * conn) {
	tlock lock(*(conn->recv_mutex));
	int get, rcv;
	GCM< AES >::Decryption d;

	// header data recv
	const int head_enc_size = (sizeof (header_t)) +  AES::BLOCKSIZE;
	get = 0;
	rcv = 0;
	unsigned char buf_head[ head_enc_size ];
	memset(buf_head, 0, head_enc_size);

	do {
		get = conn->sock->Receive(&buf_head[rcv], head_enc_size - rcv, 0);
		if (get == 0) { // The other side closed the connection
			throw std::runtime_error("Error recv_packet");
		}
		rcv += get;
	} while (head_enc_size - rcv > 0);

	// header decrypt
	std::string cipher_head, recovered_head;
	string_set(&cipher_head, buf_head, head_enc_size);

	d.SetKeyWithIV(*conn->recv_key, conn->recv_key->size(), *conn->recv_iv, conn->recv_iv->size());
	try {
		StringSource s(cipher_head, true,
			new AuthenticatedDecryptionFilter(d,
				new StringSink(recovered_head)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e) {
		std::cerr << e.what() << std::endl;
	}
	header_t header;
	memcpy(&header, recovered_head.c_str(), (sizeof (header_t)));

	// body data recv
	int body_enc_size = header.packet_length + AES::BLOCKSIZE;
	get = 0;
	rcv = 0;
	uint8_t * p_body = new uint8_t[header.packet_length + CryptoPP::AES::BLOCKSIZE];
	do {
		get = conn->sock->Receive(p_body+rcv, body_enc_size-rcv, 0);
		if (get == 0) { // The other side closed the connection
			delete[] p_body;
			throw std::runtime_error("Error recv_packet");
		}
		rcv += get;
	} while (body_enc_size-rcv > 0);

	// body decrypt
	std::string cipher_body, recovered_body;
	string_set(&cipher_body, p_body, rcv);
	delete[] p_body;

	conn->recv_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_head.substr(cipher_head.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);
	d.SetKeyWithIV(*conn->recv_key, conn->recv_key->size(), *conn->recv_iv, conn->recv_iv->size());
	try {
		StringSource s(cipher_body, true,
			new AuthenticatedDecryptionFilter(d,
				new StringSink(recovered_body)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e) {
		std::cerr << e.what() << std::endl;
	}
	conn->recv_iv->Assign(reinterpret_cast<const uint8_t*>(cipher_body.substr(cipher_body.length() - AES::BLOCKSIZE, AES::BLOCKSIZE).data()), AES::BLOCKSIZE);

	Message message(header);
	assert(message.header.packet_length == recovered_body.length());
	memcpy(message.p_body, recovered_body.c_str(), message.header.packet_length);
	return message;
}

void socket_thread_function(void* arg) {
	thread_param_t *tp = (thread_param_t*)arg;
	Socket *sock = tp->sock_ptr;
	Bindy * bindy = tp->class_ptr;
	bool inits_connect = tp->inits_connect;
	conn_id_t conn_id = tp->conn_id;
	bool is_buffered = tp->is_buffered;

	Connection *conn = new Connection();
	conn->sock = sock;

	std::string remote_nodename;
	try {
		if (!inits_connect) { // this party accepts the connection
			// Initial exchange
			uint8_t username[USERNAME_LENGTH+1];
			sock->Receive(username, USERNAME_LENGTH, 0);
			username[USERNAME_LENGTH] = '\0';

			// Authorization happens here
			std::string name((const char*)username);
			bindy->bindy_state_->assign_key_by_name(name, conn->send_key);
			bindy->bindy_state_->assign_key_by_name(name, conn->recv_key);

			sock->Receive(conn->recv_iv->BytePtr(), AES::DEFAULT_KEYLENGTH, 0);
			conn->send_iv->Assign(*conn->recv_iv);

			Message m_recv1 = recv_packet(conn);
			remote_nodename.assign((const char*)m_recv1.p_body, m_recv1.header.packet_length);

			Message m_send1(bindy->get_nodename().length(), link_pkt::PacketInitReply);
			memcpy(m_send1.p_body, bindy->get_nodename().c_str(), bindy->get_nodename().length());
			send_packet(conn, &m_send1);

			Message m_recv2 = recv_packet(conn);

			Message m_send2(0, link_pkt::PacketLinkInfo);
			send_packet(conn, &m_send2);
		} else { // this party initiates the connection
			AutoSeededRandomPool prng;
			prng.GenerateBlock(*conn->send_iv, conn->send_iv->size());
			conn->recv_iv->Assign(*conn->send_iv);

			// Authorize ourselves here
			bindy->bindy_state_->assign_key_by_name(bindy->get_master_name(), conn->send_key);
			bindy->bindy_state_->assign_key_by_name(bindy->get_master_name(), conn->recv_key);

			uint8_t username[USERNAME_LENGTH];
			std::string mname = bindy->get_master_name();
			memcpy(username, mname.c_str(), USERNAME_LENGTH);
			conn->sock->Send(username, USERNAME_LENGTH, 0);
			conn->sock->Send((const uint8_t*)(conn->send_iv->BytePtr()), AES::DEFAULT_KEYLENGTH, 0);

			Message m_send1(bindy->get_nodename().length(), link_pkt::PacketInitRequest);
			memcpy(m_send1.p_body, bindy->get_nodename().c_str(), bindy->get_nodename().length());
			send_packet(conn, &m_send1);

			Message m_recv1 = recv_packet(conn);
			remote_nodename.assign((const char*)m_recv1.p_body, m_recv1.header.packet_length);

			Message m_send2(0, link_pkt::PacketLinkInfo);
			send_packet(conn, &m_send2);

			Message m_recv2 = recv_packet(conn);
		}
		// We are connected. Now update the list of connected nodes
		bindy->add_connection(conn_id, conn); // thread-safe
		DEBUG( "BINDY> added remote_nodename = " << remote_nodename << "; conn_id = " << conn_id );

		if (tp->inits_connect) { // if this is a call from connect() method, then set external flag
			tp->connect_ok = true;
		} else { // else no one waits for us and we are responsible for deletion of the param struct
			delete tp;
		}
		// Connection established, now listen for messages and reply.
		while (true) { // actually: while m.packet_type != PacketLinkTermRequest
			DEBUG( "BINDY> receiving..." );
			Message m = recv_packet(conn);
			DEBUG( "BINDY> packet received" );
			std::string s;
			string_set(&s, m.p_body, m.header.packet_length);

			//Process packet contents
			switch (m.header.packet_type) {
				//case PacketInitRequest:	; break; // should not happen
				//case PacketInitReply:	; break; // should not happen
				//case PacketLinkInfo:	; break; // deal with this (later)
				//case PacketPing:		; break; // ping functionality, maybe?
				case link_pkt::PacketData: {
					DEBUG( "BINDY> treating packet as data packet" );
					std::vector<uint8_t> v(m.header.packet_length);
					memcpy(&v.at(0), m.p_body, v.size());
					bindy->callback_data(conn_id, v);
				} break;
				//case PacketTermRequest:	; break;
				//case PacketTermReply:	; break;
				default: {
					DEBUG( "BINDY> unknown packet received, ignoring" );
				}; break; // ignore the unknown
			}
		}
	} catch (...) {
		DEBUG( "BINDY> Caught exception, deleting connection..." );
		bindy->callback_disc(conn_id); // notify that we're dropping this connection
		bindy->delete_connection(conn_id); // this calls connection dtor
		return;
	} // terminate the thread
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
	Bindy* classptr = (Bindy*)arg;
	Socket listen_sock;
	listen_sock.Create();
	listen_sock.Bind(classptr->port_, NULL);
	if (! set_socket_options(&listen_sock) )  { // all connection sockets inherit required options from listening socket
		std::cerr << "Could not set socket options." << std::endl;
		return;
	}
	listen_sock.Listen();
	int conn_id = 0;
	try {
		while (true) {
			Socket *sock = new Socket;
			sock->Create();
			listen_sock.Accept(*sock);

			thread_param_t * tparam = new thread_param_t;
			tparam->class_ptr = classptr;
			tparam->sock_ptr = sock;
			tparam->inits_connect = false;
			tparam->connect_ok = false;
			tparam->conn_id = conn_id++;
			tthread::thread * t = new tthread::thread(socket_thread_function, tparam);
			t->detach();
		}
	} catch (std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
	}
}

void BindyState::assign_key_by_name(std::string name, SecByteBlock *key) {
	if (login_key_map.count(name) == 1) {
		key->Assign(login_key_map[name].bytes, AES_KEY_LENGTH);
	}
	else {
		throw std::runtime_error("Error assign_key_by_name");
	}
}



Bindy::Bindy(std::string filename, bool is_server, bool is_buffered)
	: port_(12345), is_server_(is_server), is_buffered_(is_buffered)
{
	bindy_state_ = new BindyState();
	bindy_state_->m_datasink = NULL;
	bindy_state_->m_discnotify = NULL;
	bindy_state_->main_thread = NULL;

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
	if (is_server_ && bindy_state_->main_thread != NULL)
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

void Bindy::connect () {
	if (is_server_)
		bindy_state_->main_thread = new tthread::thread(main_thread_function, this);
}

conn_id_t Bindy::connect (std::string addr) {
	Socket * sock = NULL;
	try {
		sock = new Socket();
		sock->Create();
		if (!sock->Connect(addr.c_str(), port_))
			throw std::runtime_error("Error connecting");
	} catch (CryptoPP::Exception e) {
		std::cerr << "Error establishing connection. " << e.what() << std::endl;
		throw e;
	}
	DEBUG( "BINDY> sock connect ok" );

	thread_param_t * tparam = new thread_param_t;
	tparam->class_ptr = this;
	tparam->sock_ptr = sock;
	tparam->inits_connect = true;
	tparam->connect_ok = false;
	tparam->is_buffered = is_buffered_;

	conn_id_t new_id = 0;
	{
		tlock lock(bindy_state_->mutex);
		do {
			new_id = rand();
		} while (bindy_state_->connections.count(new_id) != 0 || new_id == 0);
		// id==0 is the single invalid state, so we don't return it
		tparam->conn_id = new_id;
	}

	tthread::thread * t = new tthread::thread(socket_thread_function, tparam);
	t->detach();
	int sleep_count = 0, sleep_time = 1;
	while (tparam->connect_ok != true) { // TODO: add timeout
		sleep_ms(sleep_time);
		sleep_count++;
	}
	delete tparam;
	DEBUG( "BINDY> waited " << sleep_count << " * " << sleep_time << "ms intervals to connect" );

	return new_id;
	// Connection list is updated in socket_thread_function if handshake was successful
}

void Bindy::send_data (conn_id_t conn_id, std::vector<uint8_t> data) {
	Message message(data.size(), link_pkt::PacketData);
	memcpy(message.p_body, &data.at(0), message.header.packet_length);

	if (bindy_state_->connections.count(conn_id) == 1) { // should be 1 exactly...
		tlock lock(bindy_state_->mutex);
		Connection * conn = bindy_state_->connections[conn_id];
		DEBUG( "BINDY> sending " << data.size() << " raw bytes..." );
		DEBUG( "BINDY> bytes =  " << hex_encode(data) );
		send_packet(conn, &message);
		DEBUG( "BINDY> data sent" );
	} else {
		DEBUG( "BINDY> send to nodename = " << nodename << ", conn_id = " << conn_id << " FAILED." );
		DEBUG( "BINDY> connection count = " << bindy_state_->connections.size() );
		throw std::runtime_error("Error send_data");
	}
}

int Bindy::read(conn_id_t conn_id, uint8_t * p, int size) {
	tlock lock(bindy_state_->mutex);
	if (bindy_state_->connections.count(conn_id) == 1) {
		Connection * c = bindy_state_->connections[conn_id];
		int i = 0;
		while (i < size && !c->buffer->empty()) {
			*(p+i) = c->buffer->front();
			c->buffer->pop_front();
			i++;
		}
		return i;
	}
	return -1;
}

int Bindy::get_data_size (conn_id_t conn_id) {
	tlock lock(bindy_state_->mutex);
	if (bindy_state_->connections.count(conn_id) == 1) {
		Connection * c = bindy_state_->connections[conn_id];
		return static_cast<int>(c->buffer->size());
	}
	return -1;
}

void Bindy::get_master_key (uint8_t* ptr) {
	if (bindy_state_->login_key_map.size() == 0) {
		throw std::runtime_error("Error get_master_key");
	}
	memcpy(ptr, &bindy_state_->master_login.key, sizeof(aes_key_t));
}

std::string Bindy::get_master_name () {
	if (bindy_state_->login_key_map.size() == 0) {
		throw std::runtime_error("Error get_master_key");
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

bool Bindy::get_is_server()
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
}

void Bindy::callback_data (conn_id_t conn_id, std::vector<uint8_t> data) {
	if (is_buffered_) { // save to buffer
		tlock lock(bindy_state_->mutex);
		for (unsigned int i=0; i<data.size(); ++i) {
			if (bindy_state_->connections.count(conn_id) == 1)
				bindy_state_->connections[conn_id]->buffer->push_back(data.at(i));
		}
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
	in_addr ip;
	sockaddr psa;
	CryptoPP::socklen_t psaLen = sizeof ( psa );
	tlock lock(bindy_state_->mutex);
	if ( psa.sa_family == AF_INET )
		ip = ((sockaddr_in*)&psa)->sin_addr;
	else
		ip.s_addr = INADDR_NONE;
	return ip;
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
