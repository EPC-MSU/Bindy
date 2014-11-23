#ifndef INC_WRAPPER_H
#define INC_WRAPPER_H

#define conn_id_invalid 0
typedef unsigned int conn_id_t; // uint32_t in bindy.h

#if defined(__cplusplus)
extern "C" {
#endif

int bindy_enumerate(unsigned int ip_addr, int enum_timeout, unsigned char ** ptr);
uint32_t bindy_open(const char * addr, uint32_t serial, int open_timeout);
bool bindy_write(conn_id_t conn_id, const unsigned char* buf, size_t size);
size_t bindy_read(conn_id_t conn_id, unsigned char* buf, size_t size);
void bindy_close(conn_id_t conn_id, int close_timeout);

#if defined(__cplusplus)
};
#endif


#endif
