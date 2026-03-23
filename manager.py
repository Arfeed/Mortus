from listener import TCPListener, UDPListener
from interrogator import Interrogator
from archiver import Archiver



class Manager:
    def __init__(self):
        self.tcp_listener = TCPListener()
        self.udp_listener = UDPListener()
        self.interrogator = Interrogator()
        self.archiver = Archiver()

    #syncs pools
    def sync(self):
        self.interrogator.packets_queue = self.tcp_listener.catched = self.udp_listener.catched
        self.interrogator.done_packets = self.archiver.waiting_packets

    def start(self):
        self.sync()

        self.tcp_listener.start()
        self.udp_listener.start()
        self.interrogator.start()
        self.archiver.start()
    
    def stop(self):
        self.tcp_listener. run = False
        self.udp_listener.run = False
        self.interrogator.run = False
        self.archiver.run = False

m = Manager()
m.start()