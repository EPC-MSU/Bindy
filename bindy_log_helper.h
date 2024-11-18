#ifndef BINDY_LOG_HELPER_H
#define BINDY_LOG_HELPER_H

#include <cstring>
#include <string>


namespace bindy {

#define STATIC_DEBUG_MESSAGE_LENGTH 2048

/**
 * Class to help use the DEBUG macro together with << stream operator plus ZF_LOG - functions !!!
 */
class bindy_log_helper {
public:

	bindy_log_helper() {
		*_buffer = 0;
	}

	bindy_log_helper &operator << (const char *text) {
		if (strlen(_buffer) + strlen(text) <= 1024)
			strcat(_buffer, text);

		return *this;
	}

	bindy_log_helper &operator << (unsigned char *text) {
		if (strlen(_buffer) + strlen((char *)text) <= STATIC_DEBUG_MESSAGE_LENGTH)
			strcat(_buffer, (char *)text);

		return *this;
	}

	bindy_log_helper &operator << (size_t number) {
		if (strlen(_buffer) < STATIC_DEBUG_MESSAGE_LENGTH - 16)
			sprintf(strchr(_buffer, 0), "%lu", (unsigned long int)number);

		return *this;
	}

	bindy_log_helper &operator << (std::string str) {
		if (strlen(_buffer) + str.length() < STATIC_DEBUG_MESSAGE_LENGTH)
			strcat(_buffer, str.data());

		return *this;
	}

	bindy_log_helper &operator << (const uint8_t arr[32]) {
		for (int i = 0; i < 32; i++) {
			if (strlen(_buffer) + 4 > STATIC_DEBUG_MESSAGE_LENGTH) break;
			sprintf(strchr(_buffer, 0), " %u", (unsigned int)arr[i]);
		}

		return *this;
	}

	const char * buffer() const { return _buffer; }
	void clear() { *_buffer = 0; }

private:

	static char _buffer[STATIC_DEBUG_MESSAGE_LENGTH];
};

char bindy_log_helper::_buffer[STATIC_DEBUG_MESSAGE_LENGTH] = "";  // static buffer initialization

}


#endif  // BINDY_LOG_HELPER
