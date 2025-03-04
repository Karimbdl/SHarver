import sys
import socket
import nmap
import json
import os
import csv
import requests
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog, QComboBox, QProgressBar, QGridLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit

class ScanThread(QThread):
    """ Thread pour exécuter le scan réseau avec options """
    scan_finished = pyqtSignal(dict)

    def __init__(self, subnet, scan_type, port_range):
        super().__init__()
        self.subnet = subnet
        self.scan_type = scan_type  # Type de scan (ex: '-T5')
        self.port_range = port_range # Plage de ports (ex: '1-1024')
        self._is_running = True

    def run(self):
        """ Exécute le scan réseau avec les options spécifiées """
        try:
            nm = nmap.PortScanner()
            arguments = f"{self.scan_type} -p {self.port_range}" # Combine scan type and port range
            nm.scan(hosts=self.subnet, arguments=arguments)

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
            self.scan_finished.emit({'error': "Nmap error: " + str(e)})
        except PermissionError as e:
            self.scan_finished.emit({'error': "Permission error: " + str(e)})
        except Exception as e:
            error_message = f"Scan error: {str(e)}"
            print(error_message)
            self.scan_finished.emit({'error': error_message})

    def stop(self):
        """ Arrête proprement le thread """
        self._is_running = False

class HarvesterApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Seahawks Harvester - Cyberpunk Edition")
        self.setGeometry(100, 100, 800, 600) # Fenêtre plus large

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.setup_ui() # Méthode pour configurer l'interface
        self.setup_styles() # Méthode pour appliquer le style cyberpunk
        self.setup_logging()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.start_scan)
        self.timer.start(3600000) # Scan toutes les heures

    def setup_ui(self):
        """ Configure les éléments de l'interface utilisateur """
        # Infos locales (en haut, en grille)
        info_grid = QGridLayout()
        self.layout.addLayout(info_grid)

        self.local_ip = self.get_local_ip()
        self.subnet = self.get_subnet()
        self.local_ip_label = QLabel(f"IP locale: {self.local_ip}")
        self.hostname_label = QLabel(f"Machine: {socket.gethostname()}")
        self.subnet_label = QLabel(f"Plage: {self.subnet}")

        info_grid.addWidget(self.local_ip_label, 0, 0)
        info_grid.addWidget(self.hostname_label, 0, 1)
        info_grid.addWidget(self.subnet_label, 1, 0, 1, 2) # Prend 2 colonnes

        # Options de scan (ligne en dessous des infos)
        scan_options_layout = QHBoxLayout()
        self.layout.addLayout(scan_options_layout)

        self.scan_type_label = QLabel("Type de scan:")
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItem("-T5 (Rapide)", "-T5") # Vitesse rapide
        self.scan_type_combo.addItem("-T4 (Modéré)", "-T4")
        self.scan_type_combo.addItem("-sS (SYN Scan)", "-sS") # SYN scan (furtif, root)
        self.scan_type_combo.addItem("-sU (UDP Scan)", "-sU") # UDP scan
        self.scan_type_combo.setCurrentIndex(0) # Rapide par défaut

        self.port_range_label = QLabel("Plage de ports:")
        self.port_range_input = QLineEdit("1-1024") # Plage par défaut

        scan_options_layout.addWidget(self.scan_type_label)
        scan_options_layout.addWidget(self.scan_type_combo)
        scan_options_layout.addWidget(self.port_range_label)
        scan_options_layout.addWidget(self.port_range_input)


        # Bouton de scan
        self.scan_button = QPushButton("Lancer le Scan Réseau")
        self.scan_button.clicked.connect(self.start_scan)
        self.layout.addWidget(self.scan_button)

        # Tableau de résultats (remplace QTextEdit)
        self.scan_results_table = QTableWidget()
        self.scan_results_table.setColumnCount(3) # Hôte, IP, Ports Ouverts
        self.scan_results_table.setHorizontalHeaderLabels(["Hôte", "Adresse IP", "Ports Ouverts"])
        self.scan_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) # Colonnes étirées
        self.layout.addWidget(self.scan_results_table)

        # Zone de status et version (en bas)
        bottom_layout = QHBoxLayout()
        self.layout.addLayout(bottom_layout)

        self.status_label = QLabel("Prêt pour le scan...")
        self.version_label = QLabel("v1.0.0 Cyberpunk")
        bottom_layout.addWidget(self.status_label)
        bottom_layout.addWidget(self.version_label)
        bottom_layout.addStretch() # Pousse la version à droite

        # Barre de progression (sous le tableau, initialement cachée)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0) # Indéterminée
        self.progress_bar.setVisible(False)
        self.layout.addWidget(self.progress_bar)

        # Bouton stop (sous la barre de progression, désactivé au début)
        self.stop_scan_button = QPushButton("Arrêter le Scan")
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.stop_scan_button.setEnabled(False)
        self.layout.addWidget(self.stop_scan_button)

        # Bouton exporter (sous le bouton stop)
        self.export_button = QPushButton("Exporter les Résultats")
        self.export_button.clicked.connect(self.export_scan_results)
        self.layout.addWidget(self.export_button)

        # Combo mode (en bas à droite)
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Mode Clair")
        self.mode_combo.addItem("Mode Sombre Cyberpunk")
        self.mode_combo.currentIndexChanged.connect(self.toggle_mode)
        bottom_layout.addWidget(self.mode_combo)

        # Label pour le nombre de machines détectées (sous le tableau)
        self.machines_count_label = QLabel("Machines détectées: 0")
        self.layout.addWidget(self.machines_count_label)


    def setup_styles(self):
        """ Applique le style cyberpunk à l'interface PyQt5 """
        cyberpunk_style = """
            QWidget {
                background-color: #111;
                color: #eee;
                font-family: 'Roboto Mono', monospace;
                font-size: 14px;
            }
            QLabel {
                color: #00FFFF; /* Cyan pour les labels */
                text-shadow: 0 0 5px rgba(0, 255, 255, 0.8);
            }
            QLineEdit, QComboBox {
                background-color: #333;
                color: #eee;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
                selection-background-color: #00FFFF;
                selection-color: #111;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #00FFFF;
                /* box-shadow: 0 0 5px rgba(0, 255, 255, 0.5);  Retiré box-shadow */
            }
            QPushButton {
                background-color: #00FFFF; /* Boutons cyan */
                color: #111;
                border: 2px solid transparent;
                border-radius: 5px;
                padding: 8px 20px;
                font-weight: bold;
                text-transform: uppercase;
                /* box-shadow: 0 0 8px rgba(0, 255, 255, 0.5); Retiré box-shadow */
            }
            QPushButton:hover {
                background-color: #111;
                color: #00FFFF;
                border-color: #00FFFF;
                /* box-shadow: 0 0 15px rgba(0, 255, 255, 0.8); Retiré box-shadow */
            }
            QPushButton:disabled {
                background-color: #555;
                color: #888;
                border-color: transparent;
                /* box-shadow: none; Retiré box-shadow */
            }
            QProgressBar {
                border: 2px solid #00FFFF;
                border-radius: 5px;
                text-align: center;
                color: #eee;
                background-color: #222;
            }
            QProgressBar::chunk {
                background-color: #00FFFF;
            }
            QTableWidget {
                background-color: #222;
                color: #eee;
                border: 1px solid #00FFFF;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #333;
                color: #00FFFF;
                padding: 4px;
                border: 1px solid #555;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #00FFFF;
                color: #111;
            }

        """
        self.setStyleSheet(cyberpunk_style)


    def get_local_ip(self):
        # ... (méthode get_local_ip inchangée) ...
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
        # ... (méthode get_subnet inchangée) ...
        if self.local_ip == '0.0.0.0':
            return '192.168.1.0/24'
        ip_parts = self.local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    def start_scan(self):
        """ Démarre le scan avec les options choisies """
        self.status_label.setText("Scan en cours...")
        self.scan_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.scan_results_table.clearContents() # Vide le tableau précédent
        self.scan_results_table.setRowCount(0) # Reset le nombre de lignes

        scan_type = self.scan_type_combo.currentData() # Récupère la donnée associée au type de scan
        port_range = self.port_range_input.text()

        self.scan_thread = ScanThread(self.subnet, scan_type, port_range)
        self.scan_thread.scan_finished.connect(self.display_scan_results)
        self.scan_thread.start()

    def display_scan_results(self, scan_result):
        """ Affiche les résultats dans le tableau et envoie au serveur """
        self.progress_bar.setVisible(False)
        self.stop_scan_button.setEnabled(False)
        if 'error' in scan_result:
            self.status_label.setText("Erreur de scan.")
            # Afficher l'erreur dans une ligne du tableau (ou une popup, plus pro)
            self.scan_results_table.setRowCount(1)
            self.scan_results_table.setItem(0, 0, QTableWidgetItem("Erreur"))
            self.scan_results_table.setItem(0, 1, QTableWidgetItem(scan_result['error']))

        else:
            self.status_label.setText("Scan terminé. Résultats affichés.")
            row_index = 0
            machine_count = 0
            for host, ports in scan_result.items():
                self.scan_results_table.insertRow(row_index)
                hostname = "Nom inconnu"  # Nom par défaut en cas d'échec
                if host != '127.0.0.1': # Ne pas tenter la résolution pour localhost (inutile)
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                    except socket.herror:
                        hostname = "Nom inconnu" # Garder le nom par défaut en cas d'erreur
                    except Exception as e: # Capture d'autres erreurs possibles (plus rare)
                        hostname = f"Erreur nom ({str(e)})" # Message d'erreur plus précis

                self.scan_results_table.setItem(row_index, 0, QTableWidgetItem(hostname)) # Nom d'hôte (résolution ou "Nom inconnu")
                self.scan_results_table.setItem(row_index, 1, QTableWidgetItem(host)) # IP
                ports_str = ", ".join(map(str, ports)) if ports else "Aucun port ouvert"
                self.scan_results_table.setItem(row_index, 2, QTableWidgetItem(ports_str)) # Ports
                row_index += 1
                machine_count += 1

            self.machines_count_label.setText(f"Machines détectées: {machine_count}")

            self.save_scan_results(scan_result)
            self.log_scan(scan_result)

            ip_address = self.local_ip
            hostname = socket.gethostname()
            self.send_data_to_nester(ip_address, hostname, scan_result)

        self.scan_button.setEnabled(True)

    def send_data_to_nester(self, ip_address, hostname, last_scan):
        # ... (méthode send_data_to_nester inchangée) ...
        url = "http://127.0.0.1:5000/api/sonde"
        data = {
            "ip_address": ip_address,
            "hostname": hostname,
            "last_scan": json.dumps(last_scan)
        }
        try:
            response = requests.post(url, json=data)
            response.raise_for_status()
            print("Données envoyées au Nester:", response.json())
        except requests.exceptions.RequestException as e:
            print("Erreur envoi Nester:", e)

    def save_scan_results(self, scan_result):
        # ... (méthode save_scan_results inchangée) ...
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
        # ... (méthode export_scan_results inchangée, mais adapter pour le tableau si besoin) ...
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Exporter résultats", "", "Text Files (*.txt);;CSV Files (*.csv)", options=options)

        if file_path:
            if file_path.endswith('.csv'):
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Host', 'IP Address', 'Open Ports'])
                    for row in range(self.scan_results_table.rowCount()):
                        host = self.scan_results_table.item(row, 0).text()
                        ip = self.scan_results_table.item(row, 1).text()
                        ports = self.scan_results_table.item(row, 2).text()
                        writer.writerow([host, ip, ports])
            else: # Pour .txt, exporter le contenu du tableau (plus propre que QTextEdit)
                with open(file_path, 'w') as f:
                    f.write("Scan Results:\n\n")
                    f.write("Host\t\tIP Address\t\tOpen Ports\n") # En-tête texte
                    f.write("-" * 50 + "\n")
                    for row in range(self.scan_results_table.rowCount()):
                        host = self.scan_results_table.item(row, 0).text()
                        ip = self.scan_results_table.item(row, 1).text()
                        ports = self.scan_results_table.item(row, 2).text()
                        f.write(f"{host}\t\t{ip}\t\t{ports}\n")


    def setup_logging(self):
        # ... (méthode setup_logging inchangée) ...
        self.log_file = "harvester.log"
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("### Seahawks Harvester Logs ###\n")

    def log_scan(self, scan_result):
        # ... (méthode log_scan inchangée) ...
        with open(self.log_file, 'a') as f:
            f.write(f"\nScan result: {scan_result}\n")

    def toggle_mode(self, index):
        """ Change mode sombre/clair + cyberpunk sombre """
        if index == 0: # Mode Clair
            self.setStyleSheet("") # Reset styles (revient au style par défaut de l'OS)
        elif index == 1: # Mode Sombre Cyberpunk
            self.setup_styles() # Réapplique le style cyberpunk

    def stop_scan(self):
        """ Arrête le scan en cours """
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_label.setText("Scan interrompu.")
            self.scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
            self.progress_bar.setVisible(False)

    def check_for_updates(self):
        # ... (méthode check_for_updates inchangée - à implémenter plus tard) ...
        pass


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = HarvesterApp()
    window.show()
    sys.exit(app.exec_())