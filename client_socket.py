import struct
import random
import time
from btcp.btcp_socket import BTCPSocket
from btcp.constants import *
from btcp.lossy_layer import LossyLayer


# bTCP client socket
# A client application makes use of the services provided by bTCP by calling connect, send, disconnect, and close
class BTCPClientSocket(BTCPSocket):
    # window_size is the size of receive_window of the server, timeout is the timeout time, receive_window contains
    # packets for the client.
    window_size = 0
    timeout = 0
    receive_window = []

    def __init__(self, window, timeout):
        super().__init__(window, timeout)
        self.timeout = TIMEOUT_TIME
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

    # Called by the lossy layer from another thread whenever a segment arrives. 
    def lossy_layer_input(self, segment):
        packet = segment[0]
        self.receive_window.append(packet)

    # Perform a three-way handshake to establish a connection with the server
    # Returns if the establishment was successful
    def connect(self):
        handshake_complete = False
        current_tries = 0

        # Try to perform handshake within number of tries
        while not handshake_complete and current_tries < TRIES:
            # Step 1 of three-way handshake
            # Send packet with x and SYN flag
            x = random.randint(0, 65535)
            packet = struct.pack('!H2xB1013x', x, SYN)
            self._lossy_layer.send_segment(packet)
            current_tries += 1

            # Step 2 of three-way handshake
            start_time = time.time()
            while time.time() - start_time < self.timeout and not handshake_complete:
                if self.receive_window:
                    # Receive packet with y, x+1 and SYN+ACK flags
                    cur_segment = self.next_packet()
                    y, x_inc, flags, self.window_size = struct.unpack('!HHBB', cur_segment[:6])

                    # Step 3 of the three-way handshake
                    if (flags == SYN + ACK) and (x_inc == x + 1):
                        # Send packet with x+1, y+1 and ACK flag, complete handshake
                        packet = struct.pack('!HHB1013x', x_inc, y + 1, ACK)
                        self._lossy_layer.send_segment(packet)
                        handshake_complete = True

        return handshake_complete

    # Send data originating from the application in a reliable way to the server using Go-Back-N
    def send(self, input_data):
        # remaining_ack is the number of packets that still need to be acknowledged
        remaining_acks = self.window_size
        finished = False

        # Convert input_data to string, then fill packets with packets meant for the server. remaining_data contains
        # the data not in packets, seq_num the sequence number of the next to be send packet
        data = bytes(input_data, 'utf-8')
        packets, remaining_data, seq_num = self.fill_window(data)

        # While there is still data to be send, and packets to be acknowledged, execute
        while not finished:
            # Send packets that are currently in packets
            for i in range(len(packets)):
                self._lossy_layer.send_segment(packets[i])

            # Start timer and check if packets arrive
            current_time = time.time()
            while time.time() - current_time < self.timeout and not finished:
                # If the client received a packet
                if self.receive_window:
                    # Assign head of receive_window to cur_segment, unpack it
                    cur_segment = self.next_packet()
                    ack_num, flags = struct.unpack('!2xHB', cur_segment[:5])
                    packet_num = self._get_seqnum(packets[0])

                    # If packet contained an ACK and the corresponding acknowledgement number is larger or equal
                    # to the acknowledgement number that is to be acknowledged, proceed
                    if flags == ACK:
                        if ack_num >= packet_num:
                            # Remove acknowledged packet
                            packets.pop(0)

                            # Timer reset
                            current_time = time.time()

                            # Decrease the number of remaining packets to be acknowledged
                            remaining_acks -= 1

                            # Check if there is any data left to send
                            if remaining_data:
                                # Construct a new packet with sequence number of the last acknowledged packet plus
                                # the receive window size, append it to packets, then send that new packet
                                seq_num = packet_num + self.window_size
                                new_packet = self._construct_packet(seq_num, remaining_data[:PAYLOAD_SIZE])
                                packets.append(new_packet)
                                self._lossy_layer.send_segment(new_packet)

                                # Decrease remaining data with the size of a data segment, increment the packets that
                                # need to be acknowledged
                                remaining_data = remaining_data[PAYLOAD_SIZE:]
                                remaining_acks += 1

                            # If there is no data left to be send, and all sent packets are acknowledged then
                            # the client is finished with sending
                            elif not remaining_data and not remaining_acks:
                                finished = True

        pass

    # Construct an array of packets with the window size of the server
    # Returns a list of size window_size containing packets, data has not been put in packets yet
    # and the next sequence number
    def fill_window(self, data):
        packets = []
        remaining = data
        seq_num = 0

        # Fill packets with packets with the corresponding window size
        for i in range(self.window_size):
            seq_num = i
            data_segment = remaining[:PAYLOAD_SIZE]
            remaining = remaining[PAYLOAD_SIZE:]
            # If data_segment is not empty, append a new packet with sequence number seq_num
            # and data_segment to packets
            if data_segment:
                packets.append(self._construct_packet(seq_num, data_segment))

        return packets, remaining, seq_num + 1

    # Construct a single packet with sequence number seq_num containing data
    # Returns a single packet with sequence number seq_num containing data
    def _construct_packet(self, seq_num, data):
        data_length = len(data)

        # Add padding to data if necessary
        for i in range(PAYLOAD_SIZE - data_length):
            data += PADDING

        # Construct packet with sequence number seq_num, data and checksum 0, then compute the
        # checksum over that packet
        pckt_no_chksum = struct.pack('!H4xHH1008s', seq_num, data_length, 0, data)
        packet = struct.pack('!H4xHH1008s', seq_num, data_length, self.in_cksum(pckt_no_chksum), data)

        return packet

    # Return the sequence number of a packet
    def _get_seqnum(self, packet):
        return int.from_bytes(packet[:2], "big")

    # Perform a handshake to terminate a connection
    def disconnect(self):
        disconnected = False
        current_tries = 0

        # While the disconnection is not completed and not exceeded the maximum amount of tries
        while not disconnected and current_tries < TRIES:
            # Step 1 of handshake, send FIN packet
            flags = FIN
            packet = struct.pack('!4xB1013x', flags)
            self._lossy_layer.send_segment(packet)

            # Step 2/3 of handshake, receive ACK+FIN then close connection
            start_time = time.time()
            while time.time() - start_time < TIMEOUT_TIME and not disconnected:
                # If there is a packet in the receive window, unpack and check for ACK+FIN flags, if there are
                # close the connection
                if self.receive_window:
                    cur_segment = self.next_packet()
                    flags = struct.unpack('!B', cur_segment[4:5])[0]
                    if flags == ACK + FIN:
                        disconnected = True
                        self.close()
        pass

    # Return the head packet in the receive window
    def next_packet(self):
        return self.receive_window.pop(0)

    # Clean up any state
    def close(self):
        self._lossy_layer.destroy()
