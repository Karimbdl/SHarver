import sys
import socket
import nmap
import json
import os
import csv
import requests
import subprocess  # Import pour la commande ping
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog, QComboBox, QProgressBar, QGridLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit
from PyQt5.QtGui import QIcon  # Import pour les icônes


class ScanThread(QThread):
    """ Thread pour exécuter le scan réseau avec options """
    scan_finished = pyqtSignal(dict)

    def __init__(self, subnet, scan_type, port_range):
        super().__init__()
        self.subnet = subnet
        self.scan_type = scan_type  # Type de scan (ex: '-T5')
        self.port_range = port_range # Plage de ports (ex: '1-1024')
        self._is_running = True
        self.wan_ping_target = "8.8.8.8" # Cible par défaut pour le ping WAN

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
                results[host] = {}  # Change to dict to store more info
                results[host]['ports'] = [] # Ports list
                if 'tcp' in nm[host]:
                    for port, details in nm[host]['tcp'].items():
                        if details['state'] == 'open':
                            results[host]['ports'].append(port)
                # Add LAN ping latency here
                lan_latency = self.get_ping_latency(host)
                results[host]['lan_latency'] = lan_latency
                # Add WAN ping latency (to 8.8.8.8)
                wan_latency = self.get_ping_latency(self.wan_ping_target) # Ping vers cible WAN
                results['wan_latency'] = wan_latency # Stocke la latence WAN globale (pas par host)
                print(f"DEBUG: ScanThread.run() - Scan results for host {host}: {results[host]}") # DEBUG

            self.scan_finished.emit(results)
        except nmap.PortScannerError as e:
            error_msg = f"Nmap error: {str(e)}"
            print(f"DEBUG: ScanThread.run() - NmapError: {error_msg}") # DEBUG
            self.scan_finished.emit({'error': error_msg})
        except PermissionError as e:
            error_msg = f"Permission error: {str(e)}"
            print(f"DEBUG: ScanThread.run() - PermissionError: {error_msg}") # DEBUG
            self.scan_finished.emit({'error': error_msg})
        except Exception as e:
            error_message = f"Scan error: {str(e)}"
            print(f"DEBUG: ScanThread.run() - Generic Exception: {error_message}") # DEBUG
            print(f"DEBUG: ScanThread.run() - Exception details: {e}") # DEBUG - Print exception details
            self.scan_finished.emit({'error': error_message})

    def stop(self):
        """ Arrête proprement le thread """
        self._is_running = False

    def get_ping_latency(self, host):
        """ Mesure la latence ping vers un hôte spécifié - VERSION AMÉLIORÉE DU PARSING"""
        print(f"DEBUG: get_ping_latency() - Pinging host: {host}") # DEBUG
        try:
            process = subprocess.Popen(["ping", "-n", "1", "-w", "1000", host],  # -n 1 for 1 packet, -w 1000 timeout 1s
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            print(f"DEBUG: get_ping_latency() - Ping return code: {process.returncode}") # DEBUG
            if process.returncode == 0:
                output = stdout.decode('cp1252', errors='ignore') # DECODE AVEC CP1252 + ignore errors
                print(f"DEBUG: get_ping_latency() - Ping stdout: {output}") # DEBUG

                # Parsing AMÉLIORÉ et PLUS ROBUSTE (regex)
                import re  # Import module regex
                match = re.search(r"temps[=<]?([\d.,]+)\s*ms", output, re.IGNORECASE) # Recherche flexible "temps=...ms" ou "temps<...ms"
                if match:
                    latency_str = match.group(1).replace(",", ".") # Extrait la partie numérique et remplace virgule par point
                    try:
                        latency = float(latency_str) # Convertit en float
                        latency_ms = f"{latency:.2f} ms"
                        print(f"DEBUG: get_ping_latency() - Latency parsed (REGEX): {latency_ms}") # DEBUG
                        return latency_ms
                    except ValueError as ve:
                        print(f"DEBUG: get_ping_latency() - ValueError parsing latency (REGEX): {ve}") # DEBUG
                        return "N/A"
                else:
                    print(f"DEBUG: get_ping_latency() - No latency value found in ping output (REGEX)") # DEBUG
                    return "N/A"
            else:
                error_output = stderr.decode('utf-8', errors='ignore') # Decode stderr aussi (utf-8 + ignore errors)
                print(f"DEBUG: get_ping_latency() - Ping failed (return code != 0). Stderr: {error_output}") # DEBUG
                return "N/A" # Ping failed
        except Exception as e:
            print(f"DEBUG: get_ping_latency() - Exception during ping execution: {e}") # DEBUG
            return "N/A" # Error during ping execution


class HarvesterApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Seahawks Harvester - Cyberpunk Edition")
        self.setGeometry(100, 100, 900, 700) # Wider and taller window
        self.setWindowIcon(QIcon('icons/seahawks_logo.png')) # Application icon

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
        self.scan_button = QPushButton("Lancer le Scan")
        self.scan_button.setIcon(QIcon('icons/scan_icon.png')) # Scan icon
        self.scan_button.clicked.connect(self.start_scan)
        self.layout.addWidget(self.scan_button)

        # Tableau de résultats (remplace QTextEdit)
        self.scan_results_table = QTableWidget()
        self.scan_results_table.setColumnCount(5) # MODIFICATION : 5 colonnes maintenant (avec WAN)
        self.scan_results_table.setHorizontalHeaderLabels(["Hôte", "Adresse IP", "Ports Ouverts", "Latence LAN (Ping)", "Latence WAN (Ping)"]) # MODIFICATION : inclut "Latence WAN (Ping)"
        self.scan_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.layout.addWidget(self.scan_results_table)

        # Zone de status et version (en bas)
        bottom_layout = QHBoxLayout()
        self.layout.addLayout(bottom_layout)

        self.status_label = QLabel("Prêt pour le scan...")
        self.version_label = QLabel("v1.0.1 Cyberpunk")
        bottom_layout.addWidget(self.status_label)
        bottom_layout.addWidget(self.version_label)
        bottom_layout.addStretch() # Pousse la version à droite

        # Barre de progression (sous le tableau, initialement cachée)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0) # Indéterminée
        self.progress_bar.setVisible(False)
        self.layout.addWidget(self.progress_bar)

        # Boutons stop et exporter (sous la barre de progression, désactivé au début)
        buttons_layout = QHBoxLayout() # Layout horizontal pour les boutons stop et export
        self.layout.addLayout(buttons_layout)

        self.stop_scan_button = QPushButton("Arrêter")
        self.stop_scan_button.setIcon(QIcon('icons/stop_icon.png')) # Stop icon
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.stop_scan_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_scan_button)

        self.export_button = QPushButton("Exporter")
        self.export_button.setIcon(QIcon('icons/export_icon.png')) # Export icon
        self.export_button.clicked.connect(self.export_scan_results)
        buttons_layout.addWidget(self.export_button)

        # Combo mode (en bas à droite)
        self.mode_combo = QComboBox()
        self.mode_combo.addItem(QIcon('icons/light_mode_icon.png'), "Mode Clair") # Light mode icon
        self.mode_combo.addItem(QIcon('icons/dark_mode_icon.png'), "Mode Sombre Cyberpunk") # Dark mode icon
        self.mode_combo.currentIndexChanged.connect(self.toggle_mode)
        bottom_layout.addWidget(self.mode_combo)

        # Label pour le nombre de machines détectées (sous le tableau)
        self.machines_count_label = QLabel("Machines détectées: 0")
        self.layout.addWidget(self.machines_count_label)


    def setup_styles(self):
        """ Applique le style cyberpunk moins agressif à l'interface PyQt5 """
        cyberpunk_style = """
            QWidget {
                background-color: #222; /* Fond plus clair */
                color: #ddd; /* Texte gris plus clair */
                font-family: 'Roboto Mono', monospace;
                font-size: 14px;
            }
            QLabel {
                color: #66FFFF; /* Cyan moins intense pour les labels */
                text-shadow: 0 0 3px rgba(0, 255, 255, 0.5); /* Glow moins fort */
            }
            QLineEdit, QComboBox {
                background-color: #444; /* Inputs/ComboBox plus clairs */
                color: #eee;
                border: 1px solid #666; /* Bordure moins contrastée */
                border-radius: 3px;
                padding: 5px;
                selection-background-color: #66FFFF; /* Sélection moins intense */
                selection-color: #222;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #66FFFF;
            }
            QPushButton {
                background-color: #66FFFF; /* Boutons cyan moins intense */
                color: #222;
                border: 1px solid #66FFFF; /* Bordure cyan */
                border-radius: 5px;
                padding: 8px 20px;
                font-weight: bold;
                text-transform: uppercase;
                transition: background-color 0.3s, color 0.3s, border-color 0.3s; /* Transition plus douce */
            }
            QPushButton:hover {
                background-color: #222;
                color: #66FFFF;
                border-color: #66FFFF;
            }
            QPushButton:disabled {
                background-color: #666;
                color: #999;
                border-color: #666;
            }
            QProgressBar {
                border: 1px solid #66FFFF; /* Bordure moins épaisse */
                border-radius: 5px;
                text-align: center;
                color: #eee;
                background-color: #333; /* Fond plus clair */
            }
            QProgressBar::chunk {
                background-color: #66FFFF; /* Chunk moins intense */
            }
            QTableWidget {
                background-color: #333; /* Fond plus clair */
                color: #eee;
                border: 1px solid #66FFFF; /* Bordure moins épaisse */
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #444; /* Header moins sombre */
                color: #66FFFF; /* Header cyan moins intense */
                padding: 4px;
                border: 1px solid #666; /* Bordure moins contrastée */
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #66FFFF; /* Sélection moins intense */
                color: #222;
            }
        """
        self.setStyleSheet(cyberpunk_style)


    def get_local_ip(self):
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
        if self.local_ip == '0.0.0.0':
            return '192.168.1.0/24'
        ip_parts = self.local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    def start_scan(self):
        """ Démarre le scan avec les options choisies """
        self.status_label.setText("Scan en cours...") # Feedback dans la status label
        self.scan_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setFormat("Scanning...") # Indique "Scanning..." pendant le scan
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
        self.progress_bar.setFormat("") # Reset format de la progress bar
        self.stop_scan_button.setEnabled(False)
        if 'error' in scan_result:
            self.status_label.setText(f"Erreur de scan: {scan_result['error']}") # Erreur dans status label
            # Afficher l'erreur dans une ligne du tableau (ou une popup, plus pro)
            self.scan_results_table.setRowCount(1)
            self.scan_results_table.setItem(0, 0, QTableWidgetItem("Erreur"))
            self.scan_results_table.setItem(0, 1, QTableWidgetItem("Erreur"))
            self.scan_results_table.setItem(0, 2, QTableWidgetItem(" ")) # Empty port column
            self.scan_results_table.setItem(0, 3, QTableWidgetItem(" ")) # Empty latency column
            self.scan_results_table.setItem(0, 4, QTableWidgetItem(" ")) # Empty WAN latency column


        else:
            self.status_label.setText("Scan terminé. Résultats affichés.")
            row_index = 0
            machine_count = 0
            wan_latency = scan_result.get('wan_latency', 'N/A') # AJOUTER : Lire la latence WAN depuis scan_result
            for host, data in scan_result.items(): # Iterate through data dict
                if host == 'wan_latency': # AJOUTER : Skip wan_latency entry, it's general info
                    continue
                ports = data.get('ports', []) # Get ports, default to empty list
                lan_latency = data.get('lan_latency', 'N/A') # Get LAN latency, default to 'N/A'
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
                self.scan_results_table.setItem(row_index, 3, QTableWidgetItem(lan_latency))
                self.scan_results_table.setItem(row_index, 4, QTableWidgetItem(wan_latency)) # Latency WAN (same for all hosts for now)
                row_index += 1
                machine_count += 1

            self.machines_count_label.setText(f"Machines détectées: {machine_count}")

            self.save_scan_results(scan_result)
            self.log_scan(scan_result)

            ip_address = self.local_ip
            hostname = socket.gethostname()
            self.send_data_to_nester(ip_address, hostname, scan_result)

        self.scan_button.setEnabled(True)
        self.status_label.setText(self.status_label.text() + " Données exportées.") # Confirmation export


    def send_data_to_nester(self, ip_address, hostname, last_scan): # <---- CORRECTED DEFINITION - Accepts arguments
        url = "http://127.0.0.1:5000/api/sonde"
        data = {
            "ip_address": ip_address,
            "hostname": hostname,
            "last_scan": json.dumps(last_scan)
        }
        try:
            response = requests.post(url, json=data)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            print("Data sent to Nester successfully:", response.json())
        except requests.exceptions.RequestException as e:
            print(f"Failed to send data to Nester: {e}")


    def save_scan_results(self, scan_result):
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
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Exporter résultats", "", "Text Files (*.txt);;CSV Files (*.csv)", options=options)

        if file_path:
            if file_path.endswith('.csv'):
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Host', 'IP Address', 'Open Ports', 'Latency LAN', 'Latency WAN']) # ENLEVE WAN
                    for row in range(self.scan_results_table.rowCount()):
                        host = self.scan_results_table.item(row, 0).text()
                        ip = self.scan_results_table.item(row, 1).text()
                        ports = self.scan_results_table.item(row, 2).text()
                        lan_latency = self.scan_results_table.item(row, 3).text() # Get latency from table
                        wan_latency = self.scan_results_table.item(row, 4).text()
                        writer.writerow([host, ip, ports, lan_latency, wan_latency]) # Write latency to CSV
            else: # Pour .txt, exporter le contenu du tableau (plus propre que QTextEdit)
                with open(file_path, 'w') as f:
                    f.write("Scan Results:\n\n")
                    f.write("Host\t\tIP Address\t\tOpen Ports\t\tLatency LAN (Ping)\n") # En-tête texte ENLEVE WAN
                    f.write("-" * 80 + "\n") # Wider separator
                    for row in range(self.scan_results_table.rowCount()):
                        host = self.scan_results_table.item(row, 0).text()
                        ip = self.scan_results_table.item(row, 1).text()
                        ports = self.scan_results_table.item(row, 2).text()
                        lan_latency = self.scan_results_table.item(row, 3).text() # Get latency from table
                        f.write(f"{host}\t\t{ip}\t\t{ports}\t\t{lan_latency}\n")


    def setup_logging(self):
        self.log_file = "harvester.log"
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("### Seahawks Harvester Logs ###\n")

    def log_scan(self, scan_result):
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
            self.progress_bar.setFormat("") # Reset format progress bar


    def check_for_updates(self):
        pass


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = HarvesterApp()
    window.show()
    sys.exit(app.exec_())