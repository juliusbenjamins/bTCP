#!/usr/local/bin/python3

import argparse
from btcp.client_socket import BTCPClientSocket

# Client sends contents of file_name to the server


def send_data(file_name, window, timeout):
    file = open(file_name, "r")
    data = file.read()
    file.close()

    client = create_client(window, timeout)
    send(data, client)


def create_client(window, timeout):
    c = BTCPClientSocket(window, timeout)
    return c


def send(data, client):
    connected = client.connect()
    if connected:
        client.send(data)
        client.disconnect()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
    parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
    parser.add_argument("-i", "--input", help="File to send", default="input.file")
    args = parser.parse_args()


main()
