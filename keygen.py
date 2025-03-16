import sys
import hashlib
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                            QTextEdit, QVBoxLayout, QWidget, QMessageBox, 
                            QSpinBox, QHBoxLayout)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

class KeyGeneratorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('License Key Generator')
        self.setFixedSize(600, 600)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        hwid_label = QLabel('Paste Hardware ID here:')
        hwid_label.setFont(QFont('Arial', 12))
        layout.addWidget(hwid_label)
        
        self.hwid_input = QTextEdit()
        self.hwid_input.setFont(QFont('Courier', 14))
        self.hwid_input.setFixedHeight(70)
        layout.addWidget(self.hwid_input)
        
        days_layout = QHBoxLayout()
        
        days_label = QLabel('Number of days:')
        days_label.setFont(QFont('Arial', 12))
        days_layout.addWidget(days_label)
        
        self.days_input = QSpinBox()
        self.days_input.setFont(QFont('Arial', 12))
        self.days_input.setMinimum(1)
        self.days_input.setMaximum(365)
        self.days_input.setValue(30)
        days_layout.addWidget(self.days_input)
        
        layout.addLayout(days_layout)
        
        generate_btn = QPushButton('Generate License Key')
        generate_btn.setFont(QFont('Arial', 12))
        generate_btn.clicked.connect(self.generate_key)
        layout.addWidget(generate_btn)
        
        key_label = QLabel('Generated License Key (Click to select all):')
        key_label.setFont(QFont('Arial', 12))
        layout.addWidget(key_label)
        
        self.key_output = QTextEdit()
        self.key_output.setFont(QFont('Courier', 14))
        self.key_output.setFixedHeight(70)
        self.key_output.setReadOnly(True)
        layout.addWidget(self.key_output)
        
        self.key_info = QTextEdit()
        self.key_info.setFont(QFont('Arial', 11))
        self.key_info.setFixedHeight(100)
        self.key_info.setReadOnly(True)
        layout.addWidget(self.key_info)
        
        main_widget.setLayout(layout)
        
    def generate_key(self):
        hwid = self.hwid_input.toPlainText().strip()
        days = self.days_input.value()
        
        if not hwid:
            QMessageBox.warning(self, 'Warning', 'Please paste the Hardware ID first!')
            return
        
        secret = "YourSecretKeyHere"  # Trebuie să fie aceeași cu cea din security_system.py
        current_date = datetime.now().strftime('%Y-%m-%d')
        
        key_base = f"{hwid}:{current_date}:{days}:{secret}"
        license_key = hashlib.sha256(key_base.encode()).hexdigest()[:32]
        
        self.key_output.setPlainText(license_key)
        
        expiry_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
        info_text = f"Key Information:\n"
        info_text += f"• Valid for: {days} days\n"
        info_text += f"• Generated on: {current_date}\n"
        info_text += f"• Expires on: {expiry_date}\n"
        info_text += f"• Hardware ID: {hwid}"
        
        self.key_info.setPlainText(info_text)
        
        self.key_output.selectAll()
        
        QMessageBox.information(self, 'Success', f'License key generated successfully!\nKey is valid for {days} days.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = KeyGeneratorApp()
    window.show()
    sys.exit(app.exec_())