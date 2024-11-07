import ctypes
from typing import List, Optional
from .lowlevel import library as lib


def initialize_network() -> None:
    lib.bindy_initialize_network()


def shutdown_network() -> None:
    lib.bindy_shutdown_network()


class Bindy:
    """
    A class for creating server nodes and client nodes that can connect to each other.
    """

    def __init__(self, filename: str, is_active_node: bool, is_buffered: bool) -> None:
        """
        :param filename: the full name of the file containing a list of usernames and keys;
        :param is_active_node: the boolean value which indicates, whether created Bindy node is the active node.
        If this parameter is True, then this node is an active node which listens to and accepts connections.
        If this parameter is False, then this node is a passive node, which will only connect to other nodes when
        connect_client() method is called;
        :param is_buffered: the boolean value which indicates, whether created Bindy node uses internal buffering.
        If this parameter is True, then incoming data is stored in the buffer and may be retrieved using read() method.
        If this parameter is False, then incoming data immediately triggers callback function if the callback is set.
        """

        self._bindy = lib.bindy_create_new(ctypes.c_char_p(filename.encode("utf-8")), is_active_node, is_buffered)

    def __del__(self) -> None:
        lib.bindy_delete(self._bindy)

    def connect_client(self, server_address: str, adapter_address: str = "") -> int:
        """
        :param server_address: the IPv4 address or hostname to connect to;
        :param adapter_address: the IPv4 address of network adapter to bind to.
        :return: connection identifier.
        """

        return lib.bindy_connect_client(self._bindy, ctypes.c_char_p(server_address.encode("utf-8")),
                                        ctypes.c_char_p(adapter_address.encode("utf-8")))

    def connect_server(self) -> None:
        lib.bindy_connect_server(self._bindy)

    def disconnect(self, connection_id: int) -> None:
        """
        :param connection_id: connection identifier.
        """

        lib.bindy_disconnect(self._bindy, connection_id)

    def get_adapter_address(self) -> str:
        """
        :return: adapter address.
        """

        return lib.bindy_get_adapter_address(self._bindy).decode("utf-8")

    def get_data_size(self, connection_id: int) -> int:
        """
        :param connection_id: connection identifier.
        :return: size of data in buffer in bytes.
        """

        return lib.bindy_get_data_size(self._bindy, connection_id)

    def get_ip_address(self, connection_id: int) -> str:
        """
        :param connection_id: connection identifier.
        :return: IP address of the peer of connection identified by given connection identifier.
        """

        return lib.bindy_get_ip_address(self._bindy, connection_id).decode("utf-8")

    def get_port(self) -> int:
        """
        :return: port number.
        """

        return lib.bindy_get_port(self._bindy)

    def is_server(self) -> bool:
        """
        :return: True if the node is a server.
        """

        return lib.bindy_is_server(self._bindy)

    def list_connections(self) -> List[int]:
        """
        :return: list of active connections.
        """

        buffer = ctypes.POINTER(ctypes.c_uint32)()
        connections_number = lib.bindy_list_connections(self._bindy, ctypes.byref(buffer))
        return [buffer[i] for i in range(connections_number)]

    def read_message(self, connection_id: int) -> Optional[str]:
        """
        :param connection_id: connection identifier from which data needs to be read.
        :return: read message.
        """

        buffer_size = 1024
        buffer = (ctypes.c_uint8 * buffer_size)()
        data = []
        while True:
            read_data_length = lib.bindy_read_data(self._bindy, connection_id, buffer, buffer_size)
            if read_data_length == 0:
                break

            data.extend([chr(buffer[i]) for i in range(read_data_length)])

        return None if not data else "".join(data)

    def send_message(self, connection_id: int, message: str) -> None:
        """
        :param connection_id: connection identifier to send message to;
        :param message: text message to send.
        """

        data = (ctypes.c_uint8 * len(message))(*[ord(symbol) for symbol in message])
        lib.bindy_send_data(self._bindy, connection_id, data, len(message))
