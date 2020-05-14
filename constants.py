CLIENT_IP = 'localhost'
CLIENT_PORT = 20000
SERVER_IP = 'localhost'
SERVER_PORT = 30000
HEADER_SIZE = 10
PAYLOAD_SIZE = 1008
SEGMENT_SIZE = HEADER_SIZE + PAYLOAD_SIZE
TIMEOUT_TIME = 0.5  # Seconds
TRIES = 1000

# Flag values: bit 0 = SYN, bit 1 = ACK, bit 2 = FIN, rest of bits always 0
# This means 00000111 (7) = All flags, 00000001 (1) = SYN, 0000011 (3), SYN+ACK etc..
SYN = 1
ACK = 2
FIN = 4
NO_FLAGS = 0

# Padding byte
PADDING = b'0'
