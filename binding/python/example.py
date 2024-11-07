import argparse
import sys
import time
from bindy import Bindy, initialize_network


def print_main_info(bindy_obj: Bindy) -> None:
    print("Is server:", bindy_obj.is_server())
    print("Port:", bindy_obj.get_port())
    print("Adapter address:", bindy_obj.get_adapter_address())


def run_client(filename: str, address: str, message: str) -> None:
    bindy_obj = Bindy(filename, False, False)
    connection_id = bindy_obj.connect_client(address)
    print("Client started")
    print_main_info(bindy_obj)
    bindy_obj.send_message(connection_id, message)
    time.sleep(1)


def run_server(filename: str) -> None:
    bindy_obj = Bindy(filename, True, True)
    bindy_obj.connect_server()
    print("Server started")
    print_main_info(bindy_obj)

    while True:
        for connection_id in bindy_obj.list_connections():
            message = bindy_obj.read_message(connection_id)
            if message:
                print(f"Client from {bindy_obj.get_ip_address(connection_id)} says: {message}")

        time.sleep(0.01)


def main() -> None:
    parsed_args = parse_arguments()
    filename = parsed_args.filename
    address = parsed_args.address
    message = parsed_args.message

    initialize_network()
    if address is None:
        run_server(filename)
    else:
        run_client(filename, address, message)


def parse_arguments() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", type=str, help="Filename with keys")
    parser.add_argument("address", nargs="?", default=None, help="Server IP address")
    parser.add_argument("message", nargs="?", default=None, help="Message to server")
    parsed_args = parser.parse_args(sys.argv[1:])
    return parsed_args


if __name__ == "__main__":
    main()
