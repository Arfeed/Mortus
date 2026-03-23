import sqlite3
import tomllib
import queue
import multiprocessing



class Archiver:
    def __init__(self):
        self.waiting_packets = queue.Queue()

        self.initialize_db()

    def set_db_path(self) -> None:
        with open("mortus.toml", "rb") as f:
            config = tomllib.load(f)
        self.db_path = config["archiver"]["db_path"]

    def initialize_db(self) -> None:
        self.db = sqlite3.connect(self.db_path)
        self.cursor = self.db.cursor()
    
    def set_pool(self, common_queue : queue.Queue) -> None:
        self.waiting_packets = common_queue

#base operations
    def close(self) -> None:
        self.db.close()

    def execute(self, *args) -> list:
        self.cursor.execute(*args)
        self.db.commit()
        return self.cursor.fetchall()


#base creation
    def create_tables(self) -> None:
        self.execute("""
                        CREATE TABLE IF NOT EXISTS tcp_packets (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT,
                            ip_header_len INTEGER,
                            proto INTEGER,
                            src_ip TEXT,
                            dst_ip TEXT,
                            src_port INTEGER,
                            dst_port INTEGER,
                            session_hash TEXT,
                            seq INTEGER,
                            ack INTEGER,
                            flags TEXT,
                            tcp_header_len INTEGER,
                            payload BLOB
                        )""")

        self.execute("""
                        CREATE TABLE IF NOT EXISTS udp_packets (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT,
                            ip_header_len INTEGER,
                            proto INTEGER,
                            src_ip TEXT,
                            dst_ip TEXT,
                            src_port INTEGER,
                            dst_port INTEGER,
                            session_hash TEXT,
                            length INTEGER,
                            checksum INTEGER,
                            payload BLOB
                        )""")
    
        self.db.commit()


#get/read
    def get_tcp_packets(self, filter : str = '') -> list:
        if filter == '':
            return self.execute("SELECT * FROM tcp_packets")
        else:
            return self.execute("SELECT * FROM tcp_packets WHERE " + filter)
    
    def get_udp_packets(self, filter : str = '') -> list:
        if filter == '':
            return self.execute("SELECT * FROM udp_packets")
        else:
            return self.execute("SELECT * FROM udp_packets WHERE " + filter)
    
    def add_tcp_packet(self, packet : dict) -> None:
        self.execute("INSERT INTO tcp_packets VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tuple(packet.values()))
        self.db.commit()
    
    def add_udp_packet(self, packet : dict) -> None:
        self.execute("INSERT INTO udp_packets VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tuple(packet.values()))
        self.db.commit()


#destructible
    def clear_tcp_packets(self) -> None:
        self.execute("DELETE FROM tcp_packets")
        self.db.commit()
    
    def clear_udp_packets(self) -> None:
        self.execute("DELETE FROM udp_packets")
        self.db.commit()
    
    def delete_tcp_packet(self, packet_id : int) -> None:
        self.execute("DELETE FROM tcp_packets WHERE id = ?", (packet_id,))
        self.db.commit()
    
    def delete_udp_packet(self, packet_id : int) -> None:
        self.execute("DELETE FROM udp_packets WHERE id = ?", (packet_id,))
        self.db.commit()


#starter func and process 
    def process_waiting(self):
        try:
            while self.run:
                packet = self.waiting_packets.get()
                if packet['proto'] == 6:
                    self.add_tcp_packet(packet)
                elif packet['proto'] == 17:
                    self.add_udp_packet(packet)
                else:
                    pass
        except KeyboardInterrupt:
            self.run = False
        finally:
            self.close()
    
    def start(self) -> None:
        self.run = True
        multiprocessing.Process(target=self.process_waiting).start()