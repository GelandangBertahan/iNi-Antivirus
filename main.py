import os
import hashlib
import requests
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton, QFileDialog, QVBoxLayout, QWidget, QTextEdit, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal


def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return None

def hash_db():
    if getattr(sys, 'frozen', False):  
        base_path = sys._MEIPASS
    else:  
        base_path = os.path.dirname(os.path.abspath(__file__))

    database_file = os.path.join(base_path, 'database.txt')

    if os.path.exists(database_file):
        with open(database_file, "r") as file:
            return set(line.strip() for line in file if line.strip())
    else:
        return set()

def check_mb(hash_value):
    if not hash_value:
        return None

    api_url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {"query": "get_info", "hash": hash_value}

    try:
        response = requests.post(api_url, data=payload, headers=headers)
        data = response.json()

        if data.get("query_status") == "ok":
            return True 
        else:
            return False  
    except Exception as e:
        return None 

class scanningFile(QThread):
    progress_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, directory, hash_database):
        super().__init__()
        self.directory = directory
        self.hash_database = hash_database

    def run(self):
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                self.progress_signal.emit(f"Checking file: {file_path}")
                sha256_hash = calculate_sha256(file_path)

                if sha256_hash:
                    api_result = check_mb(sha256_hash)
                    if api_result is True:
                        self.progress_signal.emit(f"Detected and deleted: {file_path}")
                        os.remove(file_path)
                    elif sha256_hash in self.hash_database:
                        self.progress_signal.emit(f"Malware detected: {file_path}")
                    # else:
                    #     self.progress_signal.emit(f"No malware detected: {file_path}")
                else:
                    self.progress_signal.emit(f"Unable to calculate hash for file: {file_path}")
        self.finished_signal.emit()


class antivirusApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("iNi Antivirus")
        self.setGeometry(200, 200, 600, 400)

        layout = QVBoxLayout()

        self.label_status = QLabel("Status: Ready")
        layout.addWidget(self.label_status)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.button_select_dir = QPushButton("Select Directory to Scan")
        self.button_select_dir.clicked.connect(self.select_directory)
        layout.addWidget(self.button_select_dir)

        self.button_exit = QPushButton("Exit")
        self.button_exit.clicked.connect(self.close)
        layout.addWidget(self.button_exit)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.hash_database = hash_db()

        if not self.hash_database:
            QMessageBox.warning(self, "No hashes available in local database")

    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.label_status.setText(f"Scanning: {directory}")
            self.output_area.clear()
            self.start_scan(directory)

    def start_scan(self, directory):
        self.scanner_thread = scanningFile(directory, self.hash_database)
        self.scanner_thread.progress_signal.connect(self.update_output)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()

    def update_output(self, message):
        self.output_area.append(message)

    def scan_finished(self):
        self.label_status.setText("Scan completed!")
        QMessageBox.information(self, "Scan Completed", "The scan has finished.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = antivirusApp()
    window.show()
    sys.exit(app.exec_())
