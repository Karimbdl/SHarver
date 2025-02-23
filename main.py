import sys
import socket
import nmap
import json
import os
import csv
import requests  # Ajout de la bibliothèque requests pour les requêtes HTTP
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog, QComboBox, QProgressBar

class ScanThread(QThread):
    """ Thread pour exécuter le scan réseau avec détection des hôtes et des ports ouverts """
    scan_finished = pyqtSignal(dict)

    def __init__(self, subnet):
        super().__init__()
        self.subnet = subnet
        self._is_running = True  

    def run(self):
        """ Exécute le scan réseau """
        try:
            nm = nmap.PortScanner()
            
            nm.scan(hosts=self.subnet, arguments='-T5 -p 1-1024')  
            
            results = {}
            for host in nm.all_hosts():
                if not self._is_running: 
                    return
                results[host] = []
                if 'tcp' in nm[host]:
                    for port, details in nm[host]['tcp'].items():
                        if details['state'] == 'open':
                            results[host].append(port)
            
            self.scan_finished.emit(results)
        except nmap.PortScannerError as e:
            self.scan_finished.emit({'error': "Nmap n'est pas installé ou nécessite des permissions élevées (sudo)."})
        except PermissionError as e:
            self.scan_finished.emit({'error': "Permission refusée. Nmap nécessite des permissions élevées (sudo)."})
        except Exception as e:
            error_message = f"Erreur lors du scan : {str(e)}"
            print(error_message) 
            self.scan_finished.emit({'error': error_message})

    def stop(self):
        """ Arrête proprement le thread """
        self._is_running = False  

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

        self.version_label = QLabel("Version: v1.0.0")
        self.layout.addWidget(self.version_label)

        self.machines_count_label = QLabel("Nombre de machines détectées: 0")
        self.layout.addWidget(self.machines_count_label)

        self.export_button = QPushButton("Exporter les résultats")
        self.export_button.clicked.connect(self.export_scan_results)
        self.layout.addWidget(self.export_button)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Mode Clair")
        self.mode_combo.addItem("Mode Sombre")
        self.mode_combo.currentIndexChanged.connect(self.toggle_mode)
        self.layout.addWidget(self.mode_combo)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)  # Mode indéterminé
        self.layout.addWidget(self.progress_bar)
        self.progress_bar.setVisible(False)  # Initialement invisible

        self.stop_scan_button = QPushButton("Arrêter le scan")
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.layout.addWidget(self.stop_scan_button)
        self.stop_scan_button.setEnabled(False)  # Initialement désactivé

        self.setLayout(self.layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.start_scan)  # Recommence le scan à intervalles réguliers
        self.timer.start(3600000)  # Scan automatique toutes les heures (3600000 ms)

        self.setup_logging()

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
        self.stop_scan_button.setEnabled(True)  
        self.progress_bar.setVisible(True)  
        
        self.scan_thread = ScanThread(self.subnet)
        self.scan_thread.scan_finished.connect(self.display_scan_results)
        self.scan_thread.start()

    def display_scan_results(self, scan_result):
        """ Affiche les résultats du scan dans la zone de texte """
        self.progress_bar.setVisible(False)  # Désactive la barre de progression
        self.stop_scan_button.setEnabled(False)  # Désactive le bouton d'arrêt
        if 'error' in scan_result:
            self.scan_results.setText(f"Erreur lors du scan: {scan_result['error']}")
        else:
            result_text = "Hôtes détectés sur le réseau :\n"
            machine_count = 0
            for host, ports in scan_result.items():
                result_text += f"🖥 {host}\n"
                machine_count += 1
                if ports:
                    for port in ports:
                        result_text += f"  └ Port {port}: ouvert\n"
            
            self.machines_count_label.setText(f"Nombre de machines détectées: {machine_count}")
            self.scan_results.setText(result_text)

            # Enregistrer les résultats dans un fichier JSON
            self.save_scan_results(scan_result)
            self.log_scan(scan_result)

            # Envoyer les données au Nester
            ip_address = self.local_ip
            hostname = socket.gethostname()
            self.send_data_to_nester(ip_address, hostname, scan_result)
        
        self.scan_button.setEnabled(True)

    def send_data_to_nester(self, ip_address, hostname, last_scan):
        """
        Envoie les données du scan au serveur Nester via l'API REST.
        """
        url = "http://127.0.0.1:5000/api/sonde"  # URL de l'API du Nester
        data = {
            "ip_address": ip_address,
            "hostname": hostname,
            "last_scan": json.dumps(last_scan)  # Convertit les résultats du scan en JSON
        }
        try:
            response = requests.post(url, json=data)
            response.raise_for_status()  # Vérifie si la requête a réussi
            print("Données envoyées avec succès au Nester :", response.json())
        except requests.exceptions.RequestException as e:
            print("Erreur lors de l'envoi des données au Nester :", e)

    def save_scan_results(self, scan_result):
        """ Enregistre les résultats du scan dans un fichier JSON """
        filename = "scan_results.json"
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                all_results = json.load(f)
        else:
            all_results = []

        all_results.append(scan_result)

        with open(filename, 'w') as f:
            json.dump(all_results, f, indent=4)

    def export_scan_results(self):
        """ Exporte les résultats du scan sous format .txt ou .csv """
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Exporter les résultats", "", "Text Files (*.txt);;CSV Files (*.csv)", options=options)
        
        if file_path:
            if file_path.endswith('.csv'):
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Host', 'Open Ports'])
                    for host, ports in json.load(open("scan_results.json"))[-1].items():  # Dernier scan
                        writer.writerow([host, ', '.join(map(str, ports))])
            else:
                with open(file_path, 'w') as f:
                    f.write(self.scan_results.toPlainText())

    def setup_logging(self):
        """ Configure le logging pour tracer les scans et erreurs """
        self.log_file = "harvester.log"
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("### Logs de l'application Seahawks Harvester ###\n")

    def log_scan(self, scan_result):
        """ Enregistre les informations du scan dans un fichier log """
        with open(self.log_file, 'a') as f:
            f.write(f"\nScan effectué : {scan_result}\n")

    def toggle_mode(self, index):
        """ Change le mode de l'interface entre sombre et clair """
        if index == 0:  
            self.setStyleSheet("background-color: white; color: black;")
        else:  
            self.setStyleSheet("background-color: #2E2E2E; color: white;")

    def stop_scan(self):
        """ Arrête le scan en cours """
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.scan_thread.stop()  
            self.status_label.setText("Scan interrompu.")
            self.scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
            self.progress_bar.setVisible(False)

    def check_for_updates(self):
        """ Vérifie les mises à jour de l'application via un dépôt GitLab """
        pass

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = HarvesterApp()
    window.show()
    sys.exit(app.exec_())