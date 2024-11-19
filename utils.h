#ifndef UTILS_H
#define UTILS_H

#include <string>


namespace bindy {

/*!
 * The function parses the host name and port from the address.
 * @param[in] address Address.
 * @param[out] host Pointer to the string in which the host name will be written.
 * @param[out] port Pointer to an integer into which the found port will be saved. If the port is not found in the address,
 * the value -1 will be written.
 */
void parse_host_and_port(std::string *address, std::string *host, int *port);


/*!
 * The function parses port from the address.
 * @param[in] address Address.
 * @param[in] colon_position The position of the colon in the address from the end.
 * \return Found port value.
 */
int parse_port(std::string* address, size_t colon_position);

}


#endif  // UTILS_H
