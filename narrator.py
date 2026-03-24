import flask
import tomllib

from archiver import Archiver
from base64 import b64encode
from datetime import datetime, timedelta



class Narrator:
    def __init__(self):
        self.archiver = Archiver()
        self.format_pattern = "%Y-%m-%d %H:%M:%S"

        self.set_ports()

    def __del__(self):
        del self.archiver

    def set_ports(self):
        with open("mortus.toml", "rb") as f:
            config = tomllib.load(f)
        self.ports = config["listener"]["ports"]

    def form_ports(self) -> list[list]:
        res = []

        data_tcp = self.archiver.get_tcp_packets()
        data_udp = self.archiver.get_udp_packets()
        data = data_tcp + data_udp

        for port in self.ports:
            port_stat = [port]
            last_touch = datetime.now() - timedelta(days=999)
            cur_time = datetime.now()

            for packet in data:
                if packet[7] == port:
                    packet_time = datetime.strptime(packet[1], self.format_pattern)
                    last_touch = max(packet_time, last_touch)

                    if cur_time - packet_time <= timedelta(seconds=5):
                        port_stat.append(1)
                        break
                    else:
                        continue
            else:
                port_stat.append(0)
            
            if datetime.now() - last_touch >= timedelta(days=99):
                port_stat.append('-')
            else:
                port_stat.append(datetime.strftime(last_touch, self.format_pattern))

            res.append(port_stat)
        
        return res
    
    def get_suspect(self) -> str:
        suspect = ''

        data_tcp = self.archiver.get_tcp_packets()
        data_udp = self.archiver.get_udp_packets()
        data = data_tcp + data_udp

        freq = {}

        for packet in data:
            if packet[4] in freq:
                freq[packet[4]] += 1
            else:
                freq[packet[4]] = 1

        try:
            suspect = max(freq, key=freq.get)
        except ValueError:
            suspect = ''

        return suspect

    def get_active(self) -> int:
        data_tcp = self.archiver.get_tcp_packets()
        data_udp = self.archiver.get_udp_packets()
        data = data_tcp + data_udp

        freq = {}

        for packet in data:
            if packet[7] in freq:
                freq[packet[7]] += 1
            else:
                freq[packet[7]] = 1

        try:
            active = max(freq, key=freq.get)
        except ValueError:
            active = 0
        
        return active

    def get_packets(self,  src_ip = '', dst_ip = '', src_port = '', dst_port = '') -> list[list]:
        if src_ip == '' and dst_ip == '' and src_port == '' and dst_port == '':
            return self.archiver.get_tcp_packets()
        
        data_tcp = self.archiver.get_tcp_packets()
        data_udp = self.archiver.get_udp_packets()
        data = data_tcp + data_udp

        valid = [el for el in [src_ip, dst_ip, src_port, dst_port] if el != '' and el != 0]

        res = []

        for packet in data:
            filtred_inf = [packet[4], packet[5], packet[6], packet[7]]
            for i, parameter in enumerate(valid):
                if filtred_inf[i] != parameter:
                    break
            else:
                res.append(packet)
        
        return res

app = flask.Flask(__name__)
app.config["DEBUG"] = True

filters = []

global switch
switch = False

@app.route('/api/packets_tcp', methods=['GET'])
def get_packets_tcp():
    n = Narrator()
    packets = n.archiver.get_tcp_packets()
    del n

    packets = list(map(list, packets))
    for i in range(len(packets)):
        packets[i][-1] = b64encode(packets[i][-1]).decode()
    

    return flask.jsonify(packets)

@app.route('/api/packets_udp', methods=['GET'])
def get_packets_udp():
    n = Narrator()
    packets = n.archiver.get_udp_packets()
    del n

    packets = list(map(list, packets))
    for i in range(len(packets)):
        packets[i][-1] = b64encode(packets[i][-1]).decode()

    return flask.jsonify(packets)

@app.route('/api/switch', methods=['GET'])
def switch_mode():
    global switch
    switch = not switch
    return flask.redirect(flask.url_for('eventlog'))

@app.route('/api/ports', methods=['GET'])
def get_ports():
    n = Narrator()
    formed_ports = n.form_ports()

    del n

    return flask.jsonify(formed_ports)


@app.route('/', methods=['GET'])
def dashboard():
    n = Narrator()

    suspect = n.get_suspect()
    active = n.get_active()
    ports_count=len(n.ports)

    del n

    return flask.render_template('dashboard.html', suspect=suspect, freq_port=active, ports_count=ports_count)

@app.route('/eventlog', methods=['GET'])
def eventlog():
    return flask.render_template('eventlog.html', switch=switch)

app.run()