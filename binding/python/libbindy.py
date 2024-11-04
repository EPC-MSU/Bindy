import ctypes


lib = ctypes.cdll.LoadLibrary("bindy.dll")


class Bindy:

    def __init__(self, filename: str, is_active_node: bool, is_buffered: bool) -> None:
        lib.bindy_create_new.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_bool]
        lib.bindy_create_new.restype = ctypes.c_void_p

        lib.bindy_delete.argtypes = [ctypes.c_void_p]
        
        lib.bindy_connect_client.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.bindy_connect_client.restype = ctypes.c_uint32

        lib.bindy_connect_server.argtypes = [ctypes.c_void_p]

        lib.bindy_send_data.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_buffer]

        lib.bindy_set_handler.argtypes = [ctypes.c_void_p, ctypes.CFUNCTYPE]

        self._bindy = lib.bindy_create_new(ctypes.c_char_p(filename), is_active_node, is_buffered)
    
    def __del__ (self) -> None:
        lib.bindy_delete(self._bindy)
