import ctypes
from typing import List
from .libbindy import library as lib


def initialize_network() -> None:
    lib.bindy_initialize_network()


def shutdown_network() -> None:
    lib.bindy_shutdown_network()


class Bindy:

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

    def connect_client(self, server_address: str, adapter_address: str = "") -> None:
        """
        :param server_address: the IPv4 address or hostname to connect to;
        :param adapter_address: the IPv4 address of network adapter to bind to.
        """

        lib.bindy_connect_client(self._bindy, ctypes.c_char_p(server_address.encode("utf-8")),
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

    def list_connections(self) -> None:
        connections_number = lib.bindy_get_connections_number(self._bindy)
        if connections_number == 0:
            return

        buffer = (ctypes.c_uint32 * connections_number)()
        lib.bindy_list_connections(self._bindy, buffer, connections_number)

    def read_data(self, connection_id: int) -> None:
        """
        :param connection_id: connection identifier.
        """

        buffer_size = 1024
        buffer = (ctypes.c_uint8 * buffer_size)()
        real_length = lib.bindy_read_data(self._bindy, connection_id, buffer, buffer_size)
        print(real_length)

    def send_data(self, connection_id: int, data: List[int]) -> None:
        """
        :param connection_id: connection identifier.
        :param data:
        """

        pass
