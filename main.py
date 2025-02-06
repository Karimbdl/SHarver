import sys
import socket
import nmap
import subprocess
import re
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit

class ScanThread(QThread):
    """ Thread pour exécuter le scan réseau avec détection des hôtes et des ports ouverts """
    scan_finished = pyqtSignal(dict)

    def __init__(self, subnet):
        super().__init__()
        self.subnet = subnet

    def run(self):
        """ Exécute le scan réseau """
        try:
            nm = nmap.PortScanner()
            # Scan pour détecter toutes les machines sur le réseau
            nm.scan(hosts=self.subnet, arguments='-sn')
            
            results = {}
            for host in nm.all_hosts():
                results[host] = []  # Ajout de l'hôte sans ports ouverts
                
            # Scan détaillé des ports pour chaque machine détectée
            nm.scan(hosts=self.subnet, arguments='-p 1-65535 -T4')
            for host in nm.all_hosts():
                if 'tcp' in nm[host]:
                    for port, details in nm[host]['tcp'].items():
                        if details['state'] == 'open':
                            results[host].append(port)
            
            self.scan_finished.emit(results)
        except Exception as e:
            self.scan_finished.emit({'error': str(e)})

class HarvesterApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Seahawks Harvester")
        self.setGeometry(100, 100, 600, 400)

        self.layout = QVBoxLayout()

        self.local_ip = self.get_local_ip()
        self.subnet = self.get_subnet()

        self.local_ip_label = QLabel(f"IP locale: {self.local_ip}")
        self.hostname_label = QLabel(f"Nom de la machine: {socket.gethostname()}")
        self.subnet_label = QLabel(f"Plage scannée : {self.subnet}")
        
        self.layout.addWidget(self.local_ip_label)
        self.layout.addWidget(self.hostname_label)
        self.layout.addWidget(self.subnet_label)

        self.scan_button = QPushButton("Lancer le scan réseau")
        self.scan_button.clicked.connect(self.start_scan)
        self.layout.addWidget(self.scan_button)

        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        self.layout.addWidget(self.scan_results)

        self.status_label = QLabel("Prêt pour le scan...")
        self.layout.addWidget(self.status_label)

        self.setLayout(self.layout)

    def get_local_ip(self):
        """ Récupère l'IP locale de la machine """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '0.0.0.0'
        finally:
            s.close()
        return ip

    def get_subnet(self):
        """ Déduit automatiquement le sous-réseau de l'IP locale """
        if self.local_ip == '0.0.0.0':
            return '192.168.1.0/24'
        ip_parts = self.local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    def start_scan(self):
        """ Démarre un scan réseau dans un thread séparé """
        self.status_label.setText("Scan en cours...")
        self.scan_button.setEnabled(False)
        
        self.scan_thread = ScanThread(self.subnet)
        self.scan_thread.scan_finished.connect(self.display_scan_results)
        self.scan_thread.start()

    def display_scan_results(self, scan_result):
        """ Affiche les résultats du scan dans la zone de texte """
        if 'error' in scan_result:
            self.scan_results.setText(f"Erreur lors du scan: {scan_result['error']}")
        else:
            result_text = "Hôtes détectés sur le réseau :\n"
            for host, ports in scan_result.items():
                result_text += f"🖥 {host}\n"
                if ports:
                    for port in ports:
                        result_text += f"  └ Port {port}: ouvert\n"
            self.scan_results.setText(result_text)
        
        self.scan_button.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = HarvesterApp()
    window.show()
    sys.exit(app.exec_())
