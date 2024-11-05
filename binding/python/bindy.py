import ctypes
from libbindy import lib


def initialize_network() -> None:
    lib.bindy_initialize_network()


def shutdown_network() -> None:
    lib.bindy_shutdown_network()


class Bindy:

    def __init__(self, filename: str, is_active_node: bool, is_buffered: bool) -> None:
        self._bindy = lib.bindy_create_new(ctypes.c_char_p(filename.encode("utf-8")), is_active_node, is_buffered)

    def __del__ (self) -> None:
        lib.bindy_delete(self._bindy)

    def connect_client(self, server_address: str) -> None:
        lib.bindy_connect_client(self._bindy, ctypes.c_char_p(server_address.encode("utf-8")))

    def connect_server(self) -> None:
        lib.bindy_connect_server(self._bindy)
