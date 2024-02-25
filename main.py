import sys
import requests
import socket
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QWidget
)
from scapy.all import *

services = {
    7: 'Echo', 19: 'CHARGEN', 20: 'FTP-data', 21: 'FTP', 22: 'SSH/SCP/SFTP',
    23: 'Telnet', 25: 'SMTP', 42: 'WINS Replication', 43: 'WHOIS', 49: 'TACACS',
    53: 'DNS', 70: 'Gopher', 79: 'Finger', 80: 'HTTP', 88: 'Kerberos',
    102: 'Microsoft Exchange ISO-TSAP', 110: 'POP3', 113: 'Ident', 119: 'NNTP (Usenet)',
    135: 'Microsoft RPC EPMAP', 137: 'NetBIOS-ns', 138: 'NetBIOS-dgm', 139: 'NetBIOS-ssn',
    143: 'IMAP', 161: 'SNMP-agents (unencrypted)', 162: 'SNMP-trap (unencrypted)',
    177: 'XDMCP', 179: 'BGP', 194: 'IRC', 201: 'AppleTalk', 264: 'BGMP', 318: 'TSP',
    381: 'HP Openview', 383: 'HP Openview', 389: 'LDAP', 411: '(Multiple uses)',
    412: '(Multiple uses)', 427: 'SLP', 443: 'HTTPS (HTTP over SSL)', 445: 'Microsoft DS SMB',
    464: 'Kerberos', 465: 'SMTP over TLS/SSL, SSM', 497: 'Dantz Retrospect',
    500: 'IPSec / ISAKMP / IKE', 512: 'rexec', 513: 'rlogin', 514: 'syslog', 515: 'LPD/LPR',
    520: 'RIP', 521: 'RIPng (IPv6)', 540: 'UUCP', 548: 'AFP', 554: 'RTSP', 546: 'DHCPv6',
    547: 'DHCPv6', 560: 'rmonitor', 563: 'NNTP over TLS/SSL', 587: 'SMTP', 591: 'FileMaker',
    593: 'Microsoft DCOM', 596: 'SMSD', 631: 'IPP', 636: 'LDAP over TLS/SSL', 639: 'MSDP (PIM)',
    646: 'LDP (MPLS)', 691: 'Microsoft Exchange', 860: 'iSCSI', 873: 'rsync', 902: 'VMware Server',
    989: 'FTPS', 990: 'FTPS', 993: 'IMAP over SSL (IMAPS)', 995: 'POP3 over SSL (POP3S)'
}

def port_scan(target: list[str], ports: list[int] = list(services.keys())):
    results = {}
    for ip in target:
        for port in ports:
            response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            if response is not None:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                    results[(ip, port)] = 'Open'  # SYN-ACK response, port is open
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                    results[(ip, port)] = 'Closed'  # RST response, port is closed
            else:
                results[(ip, port)] = 'Filtered'  # No response, port is filtered
    return results

def is_server_available(ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(1)
            sock.sendto(b'', (ip, 0))
            return True
    except socket.error:
        return False

def detect_services(port_results):
    service_info = {}
    for target, status in port_results.items():
        ip, port = target[0], target[1]
        if ip not in service_info:
            service_info[ip] = []

        if status == 'Open':
            if port in services:
                service_info[ip].append(f"{services[port]} ({port})")
            else:
                service_info[ip].append(str(port))
    return service_info

def get_mac_address(ip_address):
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=False)[0]
    if result:
        for sent, received in result:
            mac_address = received.hwsrc
            return mac_address
    return "N/A"

def get_host_information(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        return {
            'IP Address': data['query'],
            'ISP': data['isp'],
            'Country': data['country'],
            'Region': data['regionName'],
            'City': data['city'],
            'MAC Address': get_mac_address(ip_address),
        }
    except Exception as e:
        return {
            'IP Address': ip_address,
            'ISP': 'N/A',
            'Country': 'N/A',
            'Region': 'N/A',
            'City': 'N/A',
            'MAC Address': 'N/A',
        }

def get_info(ips, ports, is_save=True, filename="info.log"):
    services = detect_services(port_scan(ips, ports))
    host_infos = [get_host_information(ip) for ip in ips]
    result = f'Available servers: {len(host_infos)}\n----------'
    for i in range(len(host_infos)):
        ser = "\n".join(services[host_infos[i]["IP Address"]])
        result += f'''\nIP Address: {host_infos[i]["IP Address"]}
IPS: {host_infos[i]["ISP"]}
Country: {host_infos[i]["Country"]}
Region: {host_infos[i]["Region"]}
City: {host_infos[i]["City"]}
MAC: {host_infos[i]["MAC Address"]}
Available services: {len(services[host_infos[i]["IP Address"]])}
{ser}
-----------'''
    if is_save:
        with open(filename, 'w') as f:
            f.write(result)
    return result

class IPCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP Address Checker")
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        self.ip_label = QLabel("IP:", central_widget)
        layout.addWidget(self.ip_label)
        self.ip_input = QLineEdit(central_widget)
        layout.addWidget(self.ip_input)
        self.port_label = QLabel("Port:", central_widget)
        layout.addWidget(self.port_label)
        self.port_input = QLineEdit(central_widget)
        layout.addWidget(self.port_input)
        self.check_button = QPushButton("Check", central_widget)
        self.check_button.clicked.connect(self.check_ip_addresses)
        layout.addWidget(self.check_button)
        self.result_text = QTextEdit(central_widget)
        layout.addWidget(self.result_text)

    def check_ip_addresses(self):
        if self.ip_input.text():
            ips = self.interface_get_ips(self.ip_input.text())
        else:
            file_path, _ = QFileDialog.getOpenFileName(self, 'Open File')
            with open(file_path, 'r') as f:
                ips = self.interface_get_ips(f.read())
        if self.port_input.text():
            ports = self.interface_get_ports(self.port_input.text())
        else:
            ports = list(services.keys())
        avail_servers = list(filter(lambda ip: is_server_available(ip), ips))
        self.result_text.clear()
        self.result_text.insertPlainText(get_info(avail_servers, ports))

    @staticmethod
    def interface_get_ips(in_ips):
        res = []
        for ip in in_ips.split(','):
            ip_spl = [i.strip() for i in ip.split('.')]
            if len(ip_spl) == 4:
                if ip_spl[-1].startswith('*'):
                    start, stop = [int(i) for i in ip_spl[-1][2:-1].split('-')]
                    for i in range(start, stop+1):
                        res.append(".".join(ip_spl[:3] + [str(i)]))
                else:
                    res.append(".".join(ip_spl))
        return res

    @staticmethod
    def interface_get_ports(in_ports):
        res = []
        for port in in_ports.split(","):
            res.append(int(port.strip()))
        return res

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IPCheckerApp()
    window.setGeometry(100, 100, 400, 400)
    window.show()
    sys.exit(app.exec_())
