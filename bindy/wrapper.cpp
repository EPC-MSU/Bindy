#include "bindy.h"

typedef unsigned char byte;
#include "wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Timeout in milliseconds
#define SLEEP_WAIT_TIME 10000

Bindy* bindy = NULL;

bool bindy_init()
{
	if (bindy != NULL)
		return true; // assumes old bindy is alive
	try {
		#if defined(WIN32) || defined (WIN64)
		CryptoPP::Socket::StartSockets();
		#endif

		bindy = new Bindy("keyfile.bin", false, true); // is_server == false, is_buffered == true
	} catch (...) {
		bindy = NULL;
		return false;
	}

	return true;
}

int bindy_enumerate(unsigned int ip_addr, int enum_timeout, byte ** ptr)
{
	if (false == bindy_init())
		return -1;

	int devices = 0;
	byte * buf = NULL;
	try {
		std::vector<uint8_t> s;
		s.resize(20);
		for (unsigned int i=0; i<s.size(); i++) {
			s.at(i) = 0x0;
		}
		s.at(1) = 0x03;///data_pkt::EnumerateRequest; // todo changeto write_uint

		int i1 = (ip_addr & 0xFF000000) >> 24;
		int i2 = (ip_addr & 0x00FF0000) >> 16;
		int i3 = (ip_addr & 0x0000FF00) >> 8;
		int i4 = (ip_addr & 0x000000FF);

		char addr[16] = {0};
		sprintf(addr, "%d.%d.%d.%d", i1, i2, i3, i4); // because bindy uses CryptoPP sockets and they want a string
		conn_id_t enum_conn_id = bindy->connect(addr);
		bindy->send_data(enum_conn_id, s); // send enum request
		int time_elapsed = 0;
		while ( (bindy->get_data_size(enum_conn_id) == 0) && (time_elapsed < enum_timeout)) {
			sleep(SLEEP_WAIT_TIME);
			time_elapsed += SLEEP_WAIT_TIME;
		}
		int recv_size = bindy->get_data_size(enum_conn_id);
		//byte * buf = new byte[recv_size];
		buf = (byte*)malloc(recv_size);
		bindy->read(enum_conn_id, buf, recv_size);
		*ptr = buf;

		// according to current exchange protocol specification
		devices = (uint8_t)(buf[7]); ///todo check 17

		//delete[] buf;

	} catch (...) {
		std::cout << "Exception in network enumerate: " << std::endl;
	}

	return devices;
}

uint32_t bindy_open(const char * addr, uint32_t serial, int open_timeout)
{
	if (false == bindy_init())
		return conn_id_invalid;

	uint32_t conn_id = conn_id_invalid;

	std::vector<uint8_t> request;
	request.resize(4+4+8);
	for (unsigned int i=0; i<request.size(); i++) {
		request.at(i) = 0x0;
	}

	request[1] = 0x01;///data_pkt::OpenDeviceRequest;
///	uint32_to_buf(serial, &request.at(4));

	try {
		conn_id = bindy->connect((char*)addr);
		bindy->send_data(conn_id, request); // send open request
	} catch (...) {
		return conn_id_invalid;
	}
	int time_elapsed = 0;
	while ( (bindy->get_data_size(conn_id) == 0) && (time_elapsed < open_timeout) ) {
		sleep(SLEEP_WAIT_TIME);
		time_elapsed += SLEEP_WAIT_TIME;
	}

	int recv_size = bindy->get_data_size(conn_id);
	byte * buf = new byte[recv_size];
	bindy->read(conn_id, buf, recv_size);
	bool open_ok = (0 == buf[17 ]); /// todo check
	delete[] buf;

	if (!open_ok) {
		return conn_id_invalid;
	}

	return conn_id;
}

bool bindy_write(conn_id_t conn_id, const byte* buf, size_t size)
{
	if (false == bindy_init())
		return false;

	bool is_ok = true;

	std::vector<uint8_t> s;
	s.resize(4+4+8+size);
	for (unsigned int i=0; i<s.size(); i++) {
		s.at(i) = 0x0;
	}
	s[1] = 0x00; ///data_pkt::RawData;
	uint32_t serial = 0000;//serial_by_device_id(handle);
	//uint32_to_buf(serial, &s[4]);
	memcpy(&s[16], buf, size);
	try {
		bindy->send_data(conn_id, s);
	} catch (...) {
		is_ok = false;
	}

	return is_ok;
}

size_t bindy_read(conn_id_t conn_id, byte* buf, size_t size)
{
	if (false == bindy_init())
		return -1;

	return bindy->read(conn_id, buf, size);
}

void bindy_close(conn_id_t conn_id, int close_timeout)
{
	if (false == bindy_init())
		return;

	std::vector<uint8_t> request;
	request.resize(4+4+8);
	for (unsigned int i=0; i<request.size(); i++) {
		request.at(i) = 0x0;
	}
	request[1] = 0x04;///data_pkt::CloseDeviceRequest;
///	uint32_t serial = dm->serial;
///	uint32_to_buf(serial, &request.at(4));

	try {
		bindy->send_data(conn_id, request); // send close request
	} catch (...) {
		; // whatever; server will close the device when socket is closed
	}
	int time_elapsed = 0;
	while ( (bindy->get_data_size(conn_id) == 0) && (time_elapsed < close_timeout)) {
		sleep(SLEEP_WAIT_TIME);
		time_elapsed += SLEEP_WAIT_TIME;
	}

}

#if defined(__cplusplus)
};
#endif
