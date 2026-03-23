from listener import TCPListener, UDPListener
from interrogator import Interrogator
from archiver import Archiver

import queue



class Manager:
    def __init__(self):
        self.tcp_listener = TCPListener()
        self.udp_listener = UDPListener()
        self.interrogator = Interrogator()
        self.archiver = Archiver()

    def start(self):
        self.common_pool = queue.Queue()

        self.tcp_listener.set_out_pool(self.common_pool)
        self.udp_listener.set_out_pool(self.common_pool)
        self.interrogator.set_pool(self.common_pool)
        self.archiver.set_pool(self.interrogator.done_packets)

        self.tcp_listener.start()
        self.udp_listener.start()
        self.interrogator.start()
        self.archiver.start()

m = Manager()
m.start()

print("Running...")
while True:
    input()
    print(m.archiver.get_tcp_packets())
