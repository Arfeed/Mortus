import flask
import tomllib

from archiver import Archiver
from base64 import b64encode
from datetime import datetime, timedelta



class Narrator:
    def __init__(self, archiver : Archiver = None):
        self.archiver = archiver
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

        frequency = {}

        for packet in data:
            if packet[4] in frequency:
                frequency[packet[4]] += 1
            else:
                frequency[packet[4]] = 1

        suspect = max(frequency, key=frequency.get)

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
        
        return max(freq, key=freq.get)



app = flask.Flask(__name__)
app.config["DEBUG"] = True


@app.route('/api/packets', methods=['GET'])
def get_packets():
    a = Archiver()
    packets = list(map(list, a.get_tcp_packets()))

    for i in range(len(packets)):
        packets[i][-1] = b64encode(packets[i][-1]).decode()

    del a
    return flask.jsonify(packets)

@app.route('/api/ports', methods=['GET'])
def get_ports():
    n = Narrator(Archiver())
    formed_ports = n.form_ports()

    del n

    return flask.jsonify(formed_ports)


@app.route('/', methods=['GET'])
def dashboard():
    n = Narrator(Archiver())

    suspect = n.get_suspect()
    active = n.get_active()
    ports_count=len(n.ports)

    del n

    return flask.render_template('dashboard.html', suspect=suspect, freq_port=active, ports_count=ports_count)

@app.route('/eventlog', methods=['GET'])
def eventlog():
    return flask.render_template('eventlog.html')

app.run()