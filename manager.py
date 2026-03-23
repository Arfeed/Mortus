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
        common_pool = queue.Queue()

        self.tcp_listener.set_out_pool(common_pool)
        self.udp_listener.set_out_pool(common_pool)
        self.interrogator.set_pool(common_pool)
        self.archiver.set_pool(common_pool)

        self.tcp_listener.start()
        self.udp_listener.start()
        self.interrogator.start()
        self.archiver.start()
