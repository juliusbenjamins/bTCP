import struct


class BTCPSocket:
    def __init__(self, window, timeout):
        self._window = window
        self._timeout = timeout

    # Return the Internet checksum of data
    @staticmethod
    def in_cksum(data):
        cksum = 0
        for i in range(0, len(data), 2):
            data_in_16 = data[i] + data[i+1]
            partial_sum = cksum + data_in_16
            cksum = (partial_sum & 0xffff) + (partial_sum >> 16)

        return ~cksum & 0xffff

