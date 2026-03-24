# Mortus: Investigator of the dead
Mortus is a utility designed to counter network reconnaissance. Network reconnaissance involves port pinging and connection attempts to open ports. The most popular network reconnaissance tool today, Nmap, offers a stealth scanning mode designed to prevent attackers from identifying themselves. Stealth mode works by sending single SYN packets to a port, relying on the fact that standard security systems don't register single packets. Mortus is able to detect such scanning attempts by analyzing raw packets arriving on the port.

# Installation
## Unix
```bash
git clone https://github.com/Arfeed/Mortus
cd Mortus
sudo python3 manager.py
```
## Windows
Powershell as administrator
```powershell
git clone https://github.com/Arfeed/Mortus
cd Mortus
python manager.py
```


# Interface
After installation, if you want to run the built-in web interface, you should do this.\
**WARNING: The interface only visualizes and analyzes data from the utility database. For the utility itself to work, you also need to run manager.py**

## Unix\Windows
```
cd Mortus
source venv/bin/activate
python narrator.py
```

# Technical information
Mortus has four modules:
 - Listener - listens on ports specified in the configuration file
 - Interrogator - analyzes raw packets and extracts all useful information from them, such as IP addresses, ports, load, etc.
 - Archiver - writes information to the database specified in the configuration file
 - Narrator - visualizes and analyzes the data received by the utility. Optional

 **mortus.toml** is the config file of utility.

 The Listener is divided into two streams: the TCPListener and the UDPListener. Their output pool is the input pool of the Interrogator stream, and the Interrogator's output pool is, in turn, the input pool of the Archiver stream.\
This allows the modules to process all incoming packets on the ports without delay, without interfering with each other.

Narrator uses Flask to create a web interface that takes data from the Archiver database, and then analyzes and visualizes it.
