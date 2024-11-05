import ctypes


def load_library() -> ctypes.CDLL:
    lib = ctypes.cdll.LoadLibrary("bindy.dll")
    return lib


def specify_argument_types(lib: ctypes.CDLL) -> None:
    lib.bindy_create_new.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_bool]
    lib.bindy_create_new.restype = ctypes.c_void_p

    lib.bindy_delete.argtypes = [ctypes.c_void_p]

    lib.bindy_adapter_address.argtypes = [ctypes.c_void_p]
    lib.bindy_adapter_address.restype = ctypes.c_char_p
    
    lib.bindy_connect_client.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.bindy_connect_client.restype = ctypes.c_uint32

    lib.bindy_connect_server.argtypes = [ctypes.c_void_p]

    lib.bindy_disconnect.argtypes = [ctypes.c_void_p]
    lib.bindy_disconnect.restype = ctypes.c_uint32

    lib.bindy_get_data_size.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.bindy_get_data_size.restype = ctypes.c_int

    lib.bindy_is_server.argtypes = [ctypes.c_void_p]
    lib.bindy_is_server.restype = ctypes.c_bool

    lib.bindy_port.argtypes = [ctypes.c_void_p]
    lib.bindy_port.restype = ctypes.c_int

    lib.bindy_send_data.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]


lib = load_library()
specify_argument_types(lib)
