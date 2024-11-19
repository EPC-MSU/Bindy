import ctypes
import ctypes.util
import platform
import os
import struct
from enum import auto, Enum
from typing import Optional


class Platform(Enum):
    """
    Enumeration of supported platforms.
    """

    DEBIAN = auto()
    WIN32 = auto()
    WIN64 = auto()


def detect_platform() -> Optional[Platform]:
    """
    :return: platform name.
    """

    if platform.system() == "Windows":
        return Platform.WIN32 if 8 * struct.calcsize("P") == 32 else Platform.WIN64

    if platform.system() == "Linux":
        return Platform.DEBIAN

    return None


def get_full_path(name: str) -> str:
    """
    :param name: file name.
    :return: full path to file.
    """

    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


def load_library() -> ctypes.CDLL:
    """
    :return: C library.
    """

    current_platform = detect_platform()
    library_name = {Platform.DEBIAN: "libbindy.so",
                    Platform.WIN32: "bindy.dll",
                    Platform.WIN64: "bindy.dll"}.get(current_platform, None)
    if library_name:
        lib_path = get_full_path(os.path.join(current_platform.name.lower(), library_name))
        return ctypes.cdll.LoadLibrary(lib_path)

    raise ValueError("Unknown platform")


def open_library() -> ctypes.CDLL:
    """
    :return: C library.
    """

    lib = load_library()
    specify_argument_types(lib)
    return lib


def specify_argument_types(lib: ctypes.CDLL) -> None:
    """
    :param lib: library for which you need to set the types of arguments and return values ​​of functions.
    """

    lib.bindy_connect_client.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.bindy_connect_client.restype = ctypes.c_uint32

    lib.bindy_connect_server.argtypes = [ctypes.c_void_p]

    lib.bindy_create_new.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_bool, ctypes.c_int]
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


library = open_library()
