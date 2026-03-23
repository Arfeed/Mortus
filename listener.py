import socket
import multiprocessing
import sys

import tomllib
import struct



class Listener:
    def __init__(self):
        self.ip = self.get_ip()
        self.ports = self.get_ports()

        self.catched = []

#gets parameters from toml
    def get_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except:
            return '127.0.0.1'
        finally:
            s.close()

    def get_ports(self) -> list:
        try:
            with open('mortus.toml', 'rb') as f:
                data = tomllib.load(f)
            return data['listener']['ports']
        except:
            return []
    

#syncs queues
    def set_out_pool(self, common_queue : list) -> None:
        self.catched = common_queue


#closes socket properly
    def close_socket(self) -> None:
        self.socket.close()

#checks packet for ip and port
    def check_packet(self, packet : bytes) -> bool:
        ip_len = (packet[0] & 0x0F) * 4

        dst_ip = socket.inet_ntoa(packet[16:20])
        dst_port = struct.unpack('!H', packet[ip_len+2:ip_len+4])[0]

        if dst_ip == self.ip and dst_port in self.ports:
            return True
        else:
            return False



class TCPListener(Listener):
    def __init__(self):
        super().__init__()

        self.socket = self.__create_socket()
        self.socket.settimeout(1)
    
    def __create_socket(self) -> socket.socket:
        try:
            return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except PermissionError:
            print("Not enough rights. Try sudo.")
            sys.exit(1)


#threads func and starter
    def listen(self) -> None:
        try:
            while self.run:
                try:
                    packet, _ = self.socket.recvfrom(65535)
                    if self.check_packet(packet):
                        self.catched.append(packet)

                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            self.run = False
        finally:
            self.close_socket()

    def start(self) -> None:
        self.run = True
        multiprocessing.Process(target=self.listen).start()



class UDPListener(Listener):
    def __init__(self):
        super().__init__()

        self.socket = self.__create_socket()
        self.socket.settimeout(1)

    def __create_socket(self) -> socket.socket:
        try:
            return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except PermissionError:
            print("Not enough rights. Try sudo.")
            sys.exit(1)


#threads func and starter
    def listen(self) -> None:
        try:
            while self.run:
                try:
                    packet, _ = self.socket.recvfrom(65535)
                    if self.check_packet(packet):
                        self.catched.append(packet)

                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            self.run = False
        finally:
            self.close_socket()

    def start(self) -> None:
        self.run = True
        multiprocessing.Process(target=self.listen).start()