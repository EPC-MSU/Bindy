import ctypes
from libbindy import lib


class Bindy:

    def __init__(self, filename: str, is_active_node: bool, is_buffered: bool) -> None:
        self._bindy = lib.bindy_create_new(ctypes.c_char_p(filename), is_active_node, is_buffered)
    
    def __del__ (self) -> None:
        lib.bindy_delete(self._bindy)
