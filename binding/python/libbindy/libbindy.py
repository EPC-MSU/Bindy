import ctypes


def load_library() -> ctypes.CDLL:
    lib = ctypes.cdll.LoadLibrary("bindy.dll")
    return lib


def specify_argument_types(lib: ctypes.CDLL) -> None:
    lib.bindy_connect_client.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.bindy_connect_client.restype = ctypes.c_uint32

    lib.bindy_connect_server.argtypes = [ctypes.c_void_p]

    lib.bindy_create_new.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_bool]
    lib.bindy_create_new.restype = ctypes.c_void_p

    lib.bindy_delete.argtypes = [ctypes.c_void_p]

    lib.bindy_disconnect.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    lib.bindy_get_adapter_address.argtypes = [ctypes.c_void_p]
    lib.bindy_get_adapter_address.restype = ctypes.c_char_p

    lib.bindy_get_connections_number.argtypes = [ctypes.c_void_p]
    lib.bindy_get_connections_number.restype = ctypes.c_size_t

    lib.bindy_get_data_size.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.bindy_get_data_size.restype = ctypes.c_int

    lib.bindy_get_ip_address.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.bindy_get_ip_address.restype = ctypes.c_char_p

    lib.bindy_get_port.argtypes = [ctypes.c_void_p]
    lib.bindy_get_port.restype = ctypes.c_int

    lib.bindy_initialize_network.argtypes = []

    lib.bindy_is_server.argtypes = [ctypes.c_void_p]
    lib.bindy_is_server.restype = ctypes.c_bool

    lib.bindy_list_connections.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_uint32))]
    lib.bindy_list_connections.restype = ctypes.c_size_t

    lib.bindy_read_data.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int]
    lib.bindy_read_data.restype = ctypes.c_int

    lib.bindy_send_data.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

    lib.bindy_shutdown_network.argtypes = []


library = load_library()
specify_argument_types(library)
