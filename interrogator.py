import struct
import socket
import threading

from hashlib import md5
from datetime import datetime



class Interrogator:
    def __init__(self):
        self.done_packets = []
        self.packets_queue = []

    def __flags_to_str(self, flags) -> list:
        f = {
            0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH',
            0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR'
        }
        result = []
        for bit, name in f.items():
            if flags & bit:
                result.append(name)
        return result

    def set_pool(self, common_queue : list):
        self.packets_queue = common_queue

#ip header parsing
    def get_ip_header_len(self) -> int:
        return (self.packet[0] & 0x0F) * 4

    def get_protocol(self) -> str:
        return self.packet[9]

    def get_src_ip(self) -> str:
        return socket.inet_ntoa(self.packet[12:16])

    def get_dst_ip(self) -> str:
        return socket.inet_ntoa(self.packet[16:20])

    def get_src_port(self) -> int:
        return struct.unpack('!H', self.packet[self.ip_header_len:self.ip_header_len+2])[0]

    def get_dst_port(self) -> int:
        return struct.unpack('!H', self.packet[self.ip_header_len+2:self.ip_header_len+4])[0]


#protocols headers parsing
    def get_tcp_info(self) -> dict:
        work_packet = self.packet[self.ip_header_len:]

        seq = struct.unpack('!I', work_packet[4:8])[0]
        ack = struct.unpack('!I', work_packet[8:12])[0]
        offset_res = work_packet[12]
        tcp_header_len = (offset_res >> 4) * 4
        flags = work_packet[13]
        payload = work_packet[tcp_header_len:]

        return {
            'seq': seq,
            'ack': ack,
            'flags': ','.join(self.__flags_to_str(flags)),
            'tcp_header_len': tcp_header_len,
            'payload': payload
        }

    def get_udp_info(self) -> dict:
        work_packet = self.packet[self.get_ip_header_len():]

        length = struct.unpack('!H', work_packet[4:6])[0]
        checksum = struct.unpack('!H', work_packet[6:8])[0]
        payload = work_packet[8:]

        return {
            'length': length,
            'checksum': checksum,
            'payload': payload
        }

    def create_session_hash(self) -> str:
        return md5(f"{self.get_src_ip()}-{self.get_dst_ip()}-{self.get_src_port()}-{self.get_dst_port()}".encode()).hexdigest()


#combined methods
    def get_packet_info(self, packet : bytes) -> dict:
        self.packet = packet
        res = {}

        self.ip_header_len = self.get_ip_header_len()

        proto = self.get_protocol()
        if proto == 6:
            proto_info = self.get_tcp_info()
        elif proto == 17:
            proto_info = self.get_udp_info()
        else:
            proto_info = {}

        res['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        res['ip_header_len'] = self.get_ip_header_len()
        res['proto'] = proto
        res['src_ip'] = self.get_src_ip()
        res['dst_ip'] = self.get_dst_ip()
        res['src_port'] = self.get_src_port()
        res['dst_port'] = self.get_dst_port()
        res['session_hash'] = self.create_session_hash()
        res = res | proto_info

        return res


#starter func and process
    def process(self) -> None:
        try:
            while self.run:
                
                if not self.packets_queue:
                    continue

                packet = self.packets_queue.pop(-1)
                self.done_packets.append(self.get_packet_info(packet))
        
        except KeyboardInterrupt:
            self.run = False

    def start(self) -> None:
        self.run = True
        threading.Thread(target=self.process).start()
