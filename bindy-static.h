#ifndef	BINDY_STATIC_H
#define BINDY_STATIC_H

#include <memory>
#include <vector>
#include <list>
#include <string>
#include <iostream>
#include <future>

#if defined (WIN32) || defined(WIN64)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif


#if defined(BINDY_EXPORTS)
	#if defined (WIN32) || defined(WIN64)
        #define BINDY_EXPORT __declspec(dllexport)
    #else
        #define BINDY_EXPORT __attribute__((visibility("default")))
    #endif
#elif defined(BINDY_IMPORTS)
    #if defined (WIN32) || defined(WIN64)
        #define BINDY_EXPORT __declspec(dllimport)
    #else
        #define BINDY_EXPORT
    #endif
#else
    #define BINDY_EXPORT
#endif


namespace bindy
{
// bindy version
typedef struct semver_t {
	unsigned int major;
	unsigned int minor;
	unsigned int patch;
} semver_t;
const semver_t VERSION = {0, 2, 0};

// used for handshake
const size_t AUTH_DATA_LENGTH = 32;
const size_t USERNAME_LENGTH = 128;
// aes-128
const size_t AES_KEY_LENGTH = 16;

struct user_id_t {
	uint8_t bytes[AUTH_DATA_LENGTH];
//	bool operator ==(const user_id_t& other) const;
};
typedef uint8_t role_id_t;
typedef struct {
	uint8_t bytes[AES_KEY_LENGTH];
} aes_key_t;

struct user_t {
	user_id_t uid;
	std::string name;
	aes_key_t key;
	role_id_t role;
};

enum class link_pkt : uint8_t{
	PacketData = 0,
	PacketInitRequest = 1,
	PacketInitReply = 2,
	PacketLinkInfo = 3,
	PacketTermRequest = 254,
	PacketTermReply = 255,
	// Administration-related packet types
	PacketAckSuccess = 4,
	PacketAckFailure = 5,
	PacketAddUser = 6,
	PacketDelUser = 7,
	PacketChangeKey = 8,
	PacketListUsers = 9,
	PacketSetMaster = 10,
};

/*!
* Connection identifier type definition.
*/
typedef uint32_t conn_id_t;

const conn_id_t conn_id_invalid = 0;

typedef std::vector<user_t> user_vector_t;

void BINDY_EXPORT sleep_ms(size_t ms);

class SuperConnection;
class Connection;
class BindyState;

class BINDY_EXPORT Bindy {
public:

	/*!
	*	Class constructor.
	*	@param[in] filename The full name of the file containing a list of usernames and keys.
	*	@param[in] is_active_node The boolean value which indicates, whether this class is the active node.
	*	If this parameter is true, then this node is an active node which listens to and accepts connections.
	*	If this parameter is false, then this node is a passive node, which will only connect to other nodes when connect() method is called.
	*	@param[in] is_buffered The boolean value which indicates whether this class uses internal buffering.
	*	If this parameter is true, then incoming data is stored in the buffer and may be retrieved using "read" function.
	*	If this parameter is false, then incoming data immediately triggers callback function if the callback is set.
	*/
	Bindy(std::string filename, bool is_active_node, bool is_buffered);

	/*!
	*	Class destructor.
	*	Note: calling the destructor does not immediately terminate all threads created by the class.
	*/
	~Bindy();

	/*!
	*	Sets the callback function which will receive unstructured data from the peers.
	*	@param[in] datasink Pointer to the callback function which will process the data.
	*/
	user_id_t add_user_local(const std::string &username, const aes_key_t &key, const user_id_t &uid, const role_id_t &role);
	user_id_t add_user_local(const std::string &username, const aes_key_t &key, const user_id_t &uid);
	user_id_t add_user_local(const std::string &username, const aes_key_t &key);
	void del_user_local(const user_id_t &uuid);
	void change_key_local(const user_id_t &uuid, const aes_key_t &key);
	user_vector_t list_users_local();
	user_vector_t list_users_local(std::function<bool(user_t&)>);
	void set_master_local(const user_id_t &uuid);


	std::future<user_id_t> add_user_remote(const conn_id_t conn_id, const std::string &username, const aes_key_t &key);
	std::future<void> del_user_remote(const conn_id_t conn_id, const user_id_t &uuid);
	std::future<void> change_key_remote(const conn_id_t conn_id, const user_id_t &uuid, const aes_key_t &key);
	std::future<user_vector_t> list_users_remote(const conn_id_t conn_id);
	std::future<void> set_master_remote(const conn_id_t conn_id, const user_id_t &uuid);

	/*!
	*	Imports user from external sqlite-based state file.
	*	@param[in] path Filesystem path to external sqlite-based state file.
	*/
	void import_users_from_keyfile(const std::string path);

	/*!
	*	Creates new sqlite-based state file, containing single local user from currently used state file.
	*	@param[in] uid Find user for export by identifier.
	*	@param[in] path Filesystem path where new sqlite-based state file is to be created.
	*/
	void export_user_to_keyfile(const user_id_t& uid, const std::string path);

	/*!
	*	Sets the callback function which will receive unstructured data from the peers.
	*	@param[in] datasink Pointer to the callback function which will process the data.
	*/
	void set_handler(void(*datasink)(conn_id_t conn_id, std::vector<uint8_t> data));

	/*!
	*	Sets the callback function which is called each time Bindy detects a connection was dropped either by another party or as a result of network failure.
	*	@param[in] discnotify Pointer to the callback function which will process the disconnect notifications.
	*/
	void set_discnotify(void(*discnotify)(conn_id_t conn_id));

	/*!
	*	Server method, starts listening on a socket in background and returns.
	*/
	void connect ();

	/*!
	*	Client method; each call to this function opens new socket to the host and establishes its own encrypted channel.
	*	@param[in] addr The IPv4 address or hostname to connect to.
	*	@param[in] adapter_addr The IPv4 address of network adapter to bind to.
	*	\return The handle to the created connection.Equals "conn_id_invalid" in case connection could not be established.
	*/
	conn_id_t connect(std::string addr, std::string adapter_addr = "");

	/*!
	*	Disconnects the channel identified by connection uid.
	*	Call to this function does not affect other connections to the same host.
	*	@param[in] conn_id Connection identifier.
	*/
	void disconnect (conn_id_t conn_id);

	/*!
	*	Sends data into the established connection.
	*	@param[in] conn_id Connection identifier.
	*	@param[in] data The data to send.
	*/
	void send_data (conn_id_t conn_id, std::vector<uint8_t> data);

	/*!
	*	Function to test whether this instance of Bindy class acts as a server (accepts connections).
	*	\return Boolean value, true is this class is server.
	*/
	bool is_server();

	/*!
	*	Returns the network adapter address which is used by Bindy to listen for connections.
	*	\return Adapter address.
	*/
	std::string adapter_addr();

	/*!
	*	Returns the port number which is used by Bindy to listen for connections.
	*	\return Port number.
	*/
	int port();

	/*!
	*	Returns the list of active connections.
	*	\return The list of connection identifiers.
	*/
	std::list<conn_id_t> list_connections();

	/*!
	*	Tries to read "size" bytes from buffer into "p"; returns amount of bytes read and removed from buffer.
	*	Used only with buffered mode.
	*	@param[in] conn_id Connection identifier.
	*	@param[out] p Pointer to the read buffer. Should be able to hold at least "size" bytes.
	*	@param[in] size Amount of bytes requested.
	*	\return Amount of bytes read.
	*/
	int read (conn_id_t conn_id, uint8_t * p, int size);

	/*!
	*	Returns amount of data in the buffer of connection identified by "conn_id".
	*	Used only with buffered mode.
	*	@param[in] conn_id Connection identifier.
	*	\return Size of data in buffer in bytes.
	*/
	int get_data_size (conn_id_t);

	/*!
	*	Returns the ip address of the peer of connection identified by "conn_id".
	*	@param[in] conn_id Connection identifier.
	*	\return Structure which contains peer address.
	*/
	in_addr get_ip(conn_id_t conn_id);

	/*!
	*	Calls CryptoPP platform-dependent network socket initializer.
	*/
	static void initialize_network();

	/*!
	*	Calls CryptoPP platform-dependent network socket de-initializer.
	*/
	static void shutdown_network();

	/*
	// not used yet
	void merge_cloud_info (login_vector_t login_vector);
	void change_master_key (login_pair_t login_pair);
	*/

private:
	friend class Connection;
	BindyState* bindy_state_;
	const int port_;
	const bool is_server_;
	const bool is_buffered_;
	std::string * padapter_addr_;
	/*!
	* Main thread of the Bindy class. Listens on an opened socket, accepts connections and spawns socket threads.
	*/
	friend void main_thread_function(void* arg);
	friend void broadcast_thread_function(void* arg);

	Bindy(const Bindy&) = delete;
	Bindy& operator=(const Bindy&) = delete;

	/*!
	*	Sets name of this node.
	*	@param[in] nodename Node name string.
	*/
	void set_nodename(std::string nodename);

	/*!
	*	Outputs name of this node.
	*	\return Node name string.
	*/
	std::string get_nodename(void);

	/*!
	*	Outputs username of the root user.
	*	\return name description
	*/
	user_t get_master();

	/*!
	*	Finds key by user name.
	*	@param[in] Username.
	*	\return  Returns valid key for this uid.
	*/
	aes_key_t key_by_uid(const user_id_t& uid);

	/*!
	*	Internal method for sending data.
	*	@param[in] conn_id Connection identifier.
	*	@param[in] data The data to send.
	*/
	void callback_data(conn_id_t conn_id, std::vector<uint8_t> data);

	/*!
	*	Internal disconnect method.
	*	@param[in] conn_id Connection identifier.
	*/
	void callback_disc(conn_id_t conn_id);

	/*!
	*	Internal method which adds connection to the connection table of the class.
	*	@param[in] conn_id Connection identifier.
	*	@param[in] Connection Pointer to the connection class, associated with this connection.
	*/
	void add_connection(conn_id_t conn_id, SuperConnection * conn);

	/*!
	*	Internal method which deletes the connection from the connection table by its identifier.
	*	@param[in] conn_id Connection identifier.
	*/
	void delete_connection(conn_id_t conn_id);
};


/*!
*	The helper class. Used to initialize and shutdown network using RAII idiom.
*/
class BindyNetworkInitializer
{
	BindyNetworkInitializer(const BindyNetworkInitializer&);
	BindyNetworkInitializer& operator=(const BindyNetworkInitializer&);
public:
	BindyNetworkInitializer()  { Bindy::initialize_network(); }
	~BindyNetworkInitializer() { Bindy::shutdown_network(); }
};

};

#endif // BINDY_STATIC_H
