#!/usr/local/bin/python3

import argparse
from btcp.server_socket import BTCPServerSocket

# Run the server with these steps:
#   Create a server socket
#   Start listening
#   Write all received data to output.file


def run_server(window, timeout):
    server = start_server(window, timeout)
    listen(server)
    data = server.received_data()
    server.close()

    text_file = open("output.file", "w")
    text_file.write(data.decode('utf-8'))
    text_file.close()


def start_server(window, timeout):
    s = BTCPServerSocket(window, timeout)
    return s


def listen(server):
    receiving = True
    while receiving:
        receiving = server.recv()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
    parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
    parser.add_argument("-o", "--output", help="Where to store the file", default="output.file")
    args = parser.parse_args()


main()
