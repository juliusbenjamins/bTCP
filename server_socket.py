import array
import struct
import random
import time

from btcp.lossy_layer import LossyLayer
from btcp.btcp_socket import BTCPSocket
from btcp.constants import *


# The bTCP server socket
# A server application makes use of the services provided by bTCP by calling accept, recv, and close
class BTCPServerSocket(BTCPSocket):
    data_buffer = b''

    receive_window = []

    seqnum_server_packet = 0
    seqnum_wanted = 0
    last_ack = 0
    timeout = 0
    window = 0

    def __init__(self, window, timeout):
        super().__init__(window, timeout)
        self.window = window
        self.timeout = timeout
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

    # Called by the lossy layer from another thread whenever a segment arrives
    def lossy_layer_input(self, segment):
        packet = segment[0]

        # Add the incoming packet to the back of the queue if it is approved
        # using the checksum
        if self._verify_cksum(packet):
            self.receive_window.append(packet)
        else:
            print("Checksum failed!")
        pass

    # Verify the checksum of packet
    def _verify_cksum(self, packet):
        received_chksum = struct.unpack('!H', packet[8:10])[0]
        if received_chksum == 0:
            return True

        buffer = array.array('B', packet)
        struct.pack_into('!H', buffer, 8, 0)
        computed_chksum = self.in_cksum(bytes(buffer))

        return received_chksum == computed_chksum

    # Wait for the client to initiate a three-way handshake and perform it
    def accept(self, cur_segment):
        handshake_complete = False
        x, flags = struct.unpack('!H2xB', cur_segment[0:5])

        # Create and send SYN + ACK
        y = random.randint(0, 65535)
        packet = struct.pack('!HH2B1012x', y, x + 1, SYN+ACK, self.window)
        self._lossy_layer.send_segment(packet)

        # Wait for ACK
        start_time = time.time()
        while time.time() - start_time < self.timeout and not handshake_complete:
            if self.receive_window:
                cur_segment = self._next_packet()
                inc_x, inc_y, flags = struct.unpack('!HHB', cur_segment[:5])

                # Complete three-way handshake
                if x + 1 == inc_x and y + 1 == inc_y and flags == ACK:
                    handshake_complete = True

        pass

    # Parse the first in line packet and handle accordingly, either:
    #   Respond to three-way handshake initiation of client
    #   Respond to close initiation of client
    #   send data in payload to the application layer
    def recv(self):
        payload = b''
        if self.receive_window:
            cur_segment = self._next_packet()
            flags = struct.unpack('!B', cur_segment[4:5])[0]
            # Respond to three-way handshake initiation of client
            if flags == SYN:
                self.accept(cur_segment)
            # Respond to close initiation of client
            elif flags == FIN:
                segment = struct.pack('!4xB1013x', ACK + FIN)
                self._lossy_layer.send_segment(segment)
                self.close()
                return False
            # Send data in payload to the application layer
            elif flags == NO_FLAGS:
                # Unpack received package
                seq_num, data_length, data = struct.unpack('!H4xH2x1008s', cur_segment)

                # Check ACK number and store data
                #   Respond with the correct Acknowledgement number,
                #   following the 'Go-Back-N' protocol
                if self.seqnum_wanted == 0:
                    if seq_num == 0:
                        packet = struct.pack('!HHB1013x', self.seqnum_server_packet, seq_num, ACK)
                        self._lossy_layer.send_segment(packet)
                        self.seqnum_server_packet += 1
                        self.seqnum_wanted += 1
                        payload = data[:data_length]
                else:
                    if seq_num == self.seqnum_wanted:
                        ack_num = seq_num
                        self.last_ack = seq_num
                        self.seqnum_wanted += 1
                        payload = data[:data_length]
                    else:
                        ack_num = self.last_ack

                    packet = struct.pack('!HHB1013x', self.seqnum_server_packet, ack_num, ACK)
                    self._lossy_layer.send_segment(packet)
                    self.seqnum_server_packet += 1
            else:
                print("Error: can't resolve packet")

        # Store all received data in data_buffer
        self.data_buffer += payload
        return True

    # Returns the next packet in the current window, using the FIFO principle
    def _next_packet(self):
        return self.receive_window.pop(0)

    # Returns the data_buffer
    def received_data(self):
        return self.data_buffer

    # Clean up any state
    def close(self):
        self._lossy_layer.destroy()