#ifndef INC_WRAPPER_H
#define INC_WRAPPER_H

#include "ximc.h"
//#include "bindy.h"

#define conn_id_invalid 0
typedef unsigned int conn_id_t; // uint32_t in bindy.h
typedef unsigned char byte;

#if defined(__cplusplus)
extern "C" {
#endif


//bool bindy_init();
int bindy_enumerate(unsigned int ip_addr, int enum_timeout, byte ** ptr);
uint32_t bindy_open(const char * addr, uint32_t serial, int open_timeout);
bool bindy_write(conn_id_t conn_id, const byte* buf, size_t size);
size_t bindy_read(conn_id_t conn_id, byte* buf, size_t size);
void bindy_close(conn_id_t conn_id, int close_timeout);


#if defined(__cplusplus)
};
#endif


#endif
