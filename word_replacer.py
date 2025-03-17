import os
import sys
import traceback
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                            QLineEdit, QVBoxLayout, QWidget, QFileDialog, 
                            QMessageBox, QTextEdit)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, pyqtSignal
from docx import Document
from security_system import SecureLicenseManager

class TechnicalDialog(QWidget):
    def __init__(self, license_manager):
        super().__init__()
        self.license_manager = license_manager
        self.setWindowTitle('Tehnic')
        self.setFixedSize(300, 300)
        self.init_ui()
        self.update_days()

    def init_ui(self):
        layout = QVBoxLayout()
        
        self.days_label = QLabel()
        self.days_label.setFont(QFont('Arial', 24))
        self.days_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.days_label)
        
        hwid_label = QLabel('Hardware ID:')
        hwid_label.setFont(QFont('Arial', 10))
        layout.addWidget(hwid_label)
        
        self.hwid_text = QTextEdit()
        self.hwid_text.setFont(QFont('Courier', 12))
        self.hwid_text.setFixedHeight(50)
        self.hwid_text.setPlainText(self.license_manager.get_hardware_id())
        self.hwid_text.setReadOnly(True)
        layout.addWidget(self.hwid_text)
        
        key_label = QLabel('Enter new license key:')
        key_label.setFont(QFont('Arial', 10))
        layout.addWidget(key_label)
        
        self.key_input = QLineEdit()
        self.key_input.setFont(QFont('Arial', 12))
        layout.addWidget(self.key_input)
        
        extend_btn = QPushButton('Extend License')
        extend_btn.setFont(QFont('Arial', 12))
        extend_btn.clicked.connect(self.extend_license)
        layout.addWidget(extend_btn)
        
        self.setLayout(layout)
    
    def update_days(self):
        is_valid, message = self.license_manager.verify_license()
        if is_valid:
            days = int(message.split(": ")[1])
            self.days_label.setText(str(days))
        else:
            self.days_label.setText("0")
    
    def extend_license(self):
        key = self.key_input.text().strip()
        if key:
            success, message = self.license_manager.save_license(key)
            if success:
                self.update_days()
                self.key_input.clear()
                QMessageBox.information(self, 'Success', 'License extended successfully!')
            else:
                QMessageBox.critical(self, 'Error', message)
        else:
            QMessageBox.warning(self, 'Warning', 'Please enter a license key')

class ActivationDialog(QWidget):
    # Definim semnalul finished
    finished = pyqtSignal(int)
    
    def __init__(self, license_manager):
        super().__init__()
        self.license_manager = license_manager
        self.init_ui()
        self.setWindowTitle('Product Activation')
        self.setFixedSize(500, 250)

    def init_ui(self):
        layout = QVBoxLayout()
        
        hwid_label = QLabel('Your Hardware ID (Click to select all):')
        hwid_label.setFont(QFont('Arial', 12))
        layout.addWidget(hwid_label)
        
        self.hwid_text = QTextEdit()
        self.hwid_text.setFont(QFont('Courier', 14))
        self.hwid_text.setFixedHeight(70)
        self.hwid_text.setPlainText(self.license_manager.get_hardware_id())
        self.hwid_text.setReadOnly(True)
        layout.addWidget(self.hwid_text)
        
        key_label = QLabel('Enter License Key:')
        key_label.setFont(QFont('Arial', 12))
        layout.addWidget(key_label)
        
        self.key_input = QLineEdit()
        self.key_input.setFont(QFont('Arial', 12))
        layout.addWidget(self.key_input)
        
        activate_btn = QPushButton('Activate')
        activate_btn.setFont(QFont('Arial', 12))
        activate_btn.clicked.connect(self.activate_license)
        layout.addWidget(activate_btn)
        
        self.setLayout(layout)
        
    def activate_license(self):
        key = self.key_input.text().strip()
        if key:
            success, message = self.license_manager.save_license(key)
            if success:
                QMessageBox.information(self, 'Success', 'License activated successfully!')
                self.close()
                self.finished.emit(1)  # Emitem semnalul cu valoarea 1 pentru succes
            else:
                QMessageBox.critical(self, 'Error', message)
        else:
            QMessageBox.warning(self, 'Warning', 'Please enter a license key')
            
    def closeEvent(self, event):
        # Emitem semnalul când dialogul este închis
        self.finished.emit(0)  # 0 pentru închidere fără activare
        super().closeEvent(event)

class WordReplacerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            self.license_manager = SecureLicenseManager()
            self.folder_path = ""
            self.init_ui()
            self.check_license()
        except Exception as e:
            QMessageBox.critical(self, 'Initialization Error', f'Error starting application: {str(e)}')
            traceback.print_exc()
        
    def init_ui(self):
        self.setWindowTitle('Word Replacer')
        self.setFixedSize(600, 400)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        self.tech_btn = QPushButton('Tehnic')
        self.tech_btn.setFont(QFont('Arial', 12))
        self.tech_btn.clicked.connect(self.show_technical)
        layout.addWidget(self.tech_btn)
        
        self.browse_btn = QPushButton('Browse Folder')
        self.browse_btn.setFont(QFont('Arial', 12))
        self.browse_btn.clicked.connect(self.browse_folder)
        layout.addWidget(self.browse_btn)
        
        find_label = QLabel('Cuvânt de înlocuit:')
        find_label.setFont(QFont('Arial', 12))
        layout.addWidget(find_label)
        
        self.find_input = QLineEdit()
        self.find_input.setFont(QFont('Arial', 12))
        layout.addWidget(self.find_input)
        
        replace_label = QLabel('Cuvânt de înlocuire:')
        replace_label.setFont(QFont('Arial', 12))
        layout.addWidget(replace_label)
        
        self.replace_input = QLineEdit()
        self.replace_input.setFont(QFont('Arial', 12))
        layout.addWidget(self.replace_input)
        
        self.start_btn = QPushButton('Start')
        self.start_btn.setFont(QFont('Arial', 12))
        self.start_btn.clicked.connect(self.start_replacement)
        layout.addWidget(self.start_btn)
        
        main_widget.setLayout(layout)
    
    def show_technical(self):
        try:
            self.tech_dialog = TechnicalDialog(self.license_manager)
            self.tech_dialog.show()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error showing technical dialog: {str(e)}')
            traceback.print_exc()
        
    def check_license(self):
        try:
            is_valid, message = self.license_manager.verify_license()
            if not is_valid:
                # Afișăm un mesaj de avertizare
                QMessageBox.warning(self, 'License Required', f'License verification failed: {message}')
                self.activation_dialog = ActivationDialog(self.license_manager)
                # Conectăm un signal pentru a reîncerca verificarea licenței
                self.activation_dialog.finished.connect(self.on_activation_finished)
                self.activation_dialog.show()
            else:
                # Mesaj de confirmare
                QMessageBox.information(self, 'License Valid', message)
        except Exception as e:
            QMessageBox.critical(self, 'License Error', f'Error checking license: {str(e)}')
            traceback.print_exc()
    
    def on_activation_finished(self, result):
        try:
            # Reîncercăm verificarea licenței
            is_valid, message = self.license_manager.verify_license()
            if is_valid:
                QMessageBox.information(self, 'License Valid', message)
            else:
                # Dacă licența nu este validă, dezactivăm butonul
                self.start_btn.setEnabled(False)
                QMessageBox.critical(self, 'License Error', 'Application will run in limited mode until a valid license is provided.')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error after activation: {str(e)}')
            traceback.print_exc()
    
    def browse_folder(self):
        try:
            self.folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
            if self.folder_path:
                QMessageBox.information(self, 'Folder Selected', f'Selected folder: {self.folder_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error browsing folder: {str(e)}')
            traceback.print_exc()
    
    def start_replacement(self):
        try:
            is_valid, message = self.license_manager.verify_license()
            if not is_valid:
                QMessageBox.critical(self, 'License Error', message)
                self.check_license()
                return

            word_to_find = self.find_input.text().strip()
            word_to_replace = self.replace_input.text().strip()

            if not self.folder_path or not word_to_find or not word_to_replace:
                QMessageBox.warning(self, 'Warning', 'Toate câmpurile trebuie completate!')
                return

            files_processed = 0
            for root, _, files in os.walk(self.folder_path):
                for file in files:
                    if file.startswith("@@") and file.endswith(".docx"):
                        file_path = os.path.join(root, file)
                        try:
                            doc = Document(file_path)
                            for paragraph in doc.paragraphs:
                                for run in paragraph.runs:
                                    if word_to_find in run.text:
                                        run.text = run.text.replace(word_to_find, word_to_replace)
                            doc.save(file_path)
                            files_processed += 1
                        except Exception as e:
                            QMessageBox.critical(self, 'Error', f'Eroare la procesarea fișierului {file_path}: {str(e)}')

            if files_processed > 0:
                QMessageBox.information(self, 'Success', f'Înlocuirea s-a terminat cu succes! S-au procesat {files_processed} fișiere.')
            else:
                QMessageBox.warning(self, 'Warning', 'Nu s-a găsit niciun fișier care să îndeplinească criteriile (nume începând cu @@ și extensie .docx).')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Eroare la procesul de înlocuire: {str(e)}')
            traceback.print_exc()

if __name__ == '__main__':
    try:
        # Configurăm afișarea excepțiilor necaptate
        def exception_hook(exctype, value, traceback_obj):
            traceback.print_exception(exctype, value, traceback_obj)
            QMessageBox.critical(None, 'Unhandled Exception',
                                 f'An unhandled exception occurred: {exctype.__name__}: {value}')
            sys.exit(1)
        
        sys.excepthook = exception_hook
        
        app = QApplication(sys.argv)
        window = WordReplacerApp()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"CRITICAL ERROR: {str(e)}")
        traceback.print_exc()
        if QApplication.instance():
            QMessageBox.critical(None, 'Fatal Error', 
                                f'A critical error occurred:\n{str(e)}')
        sys.exit(1)