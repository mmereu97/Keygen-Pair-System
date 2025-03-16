import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                            QLineEdit, QVBoxLayout, QWidget, QFileDialog, 
                            QMessageBox, QTextEdit)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
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
            else:
                QMessageBox.critical(self, 'Error', message)
        else:
            QMessageBox.warning(self, 'Warning', 'Please enter a license key')

class WordReplacerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.license_manager = SecureLicenseManager()
        self.folder_path = ""
        self.init_ui()
        self.check_license()
        
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
        self.tech_dialog = TechnicalDialog(self.license_manager)
        self.tech_dialog.show()
        
    def check_license(self):
        is_valid, message = self.license_manager.verify_license()
        if not is_valid:
            self.activation_dialog = ActivationDialog(self.license_manager)
            self.activation_dialog.show()
    
    def browse_folder(self):
        self.folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
        if self.folder_path:
            QMessageBox.information(self, 'Folder Selected', f'Selected folder: {self.folder_path}')
    
    def start_replacement(self):
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

        try:
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
                        except Exception as e:
                            QMessageBox.critical(self, 'Error', f'Eroare la procesarea fișierului {file_path}: {str(e)}')

            QMessageBox.information(self, 'Success', 'Înlocuirea s-a terminat cu succes!')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Eroare: {str(e)}')

if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    window = WordReplacerApp()
    window.show()
    sys.exit(app.exec_())