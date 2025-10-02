import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, 
    QVBoxLayout, QHBoxLayout, QMessageBox, QTableWidget, QTableWidgetItem,
    QInputDialog, QCheckBox, QComboBox,
)
from db import *
from crypto import *
import sqlite3 as sql
from ui import *
import string



class MasterPasswordWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Master Şifre Oluştur")
        self.setGeometry(200,200,400,220)  # biraz daha yükseklik verdik

        self.label1 = QLabel("Master Şifre:")
        self.input1 = QLineEdit()
        self.input1.setEchoMode(QLineEdit.EchoMode.Password)

        self.label2 = QLabel("Tekrar:")
        self.input2 = QLineEdit()
        self.input2.setEchoMode(QLineEdit.EchoMode.Password)

        # Şifreyi göster checkbox
        self.show_pw_checkbox = QCheckBox("Şifreyi Göster")
        self.show_pw_checkbox.stateChanged.connect(self.toggle_password_visibility)

        self.button = QPushButton("Oluştur")
        self.button.clicked.connect(self.create_master)

        layout = QVBoxLayout()
        layout.addWidget(self.label1)
        layout.addWidget(self.input1)
        layout.addWidget(self.label2)
        layout.addWidget(self.input2)
        layout.addWidget(self.show_pw_checkbox)
        layout.addWidget(self.button)
        self.setLayout(layout)

    def toggle_password_visibility(self):
        if self.show_pw_checkbox.isChecked():
            self.input1.setEchoMode(QLineEdit.EchoMode.Normal)
            self.input2.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.input1.setEchoMode(QLineEdit.EchoMode.Password)
            self.input2.setEchoMode(QLineEdit.EchoMode.Password)

    def create_master(self):
        pw1, pw2 = self.input1.text(), self.input2.text()
        
        if pw1 != pw2:
            QMessageBox.warning(self,"Hata","Şifreler uyuşmuyor!")
            return
        
        try:
            create_master_password(pw1)  # ValueError fırlatabilir
        except ValueError as e:
            QMessageBox.warning(self, "Zayıf Şifre", str(e))
            return

        QMessageBox.information(self,"Başarılı","Master şifre oluşturuldu!")
        self.close()
        self.login = LoginWindow()
        self.login.show()


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Şifre Kasası - Giriş")
        self.setGeometry(200,200,300,180)  # biraz daha yükseklik verdik

        self.label = QLabel("Master Şifre:")
        self.input = QLineEdit()
        self.input.setEchoMode(QLineEdit.EchoMode.Password)

        # Şifreyi göster checkbox
        self.show_pw_checkbox = QCheckBox("Şifreyi Göster")
        self.show_pw_checkbox.stateChanged.connect(self.toggle_password_visibility)

        self.button = QPushButton("Giriş Yap")
        self.button.clicked.connect(self.login)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.input)
        layout.addWidget(self.show_pw_checkbox)
        layout.addWidget(self.button)
        self.setLayout(layout)

    def toggle_password_visibility(self):
        if self.show_pw_checkbox.isChecked():
            self.input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.input.setEchoMode(QLineEdit.EchoMode.Password)

    def login(self):
        pw = self.input.text()
        if verify_master_password(pw):
            self.hide()
            self.main = MainWindow(pw)
            self.main.show()
        else:
            QMessageBox.warning(self,"Hata","Yanlış şifre!")

class MainWindow(QWidget):
    def __init__(self, master_password):
        super().__init__()
        self.master_password = master_password
        self.setWindowTitle("Şifre Kasası")
        self.setGeometry(200, 200, 700, 450)

        # Inputs
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Servis")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Kullanıcı adı")

        self.add_button = QPushButton("Hesap Ekle")
        self.add_button.clicked.connect(self.add_account_gui)

        self.list_button = QPushButton("Hesapları Listele")
        self.list_button.clicked.connect(self.ask_list_type)

        self.show_pw_checkbox = QCheckBox("Şifreleri Göster")
        self.show_pw_checkbox.stateChanged.connect(self.toggle_password_visibility)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Servis","Kullanıcı","Şifre"])
        self.table.setAlternatingRowColors(True)

        # Hesap sil ve şifre kopyala
        self.delete_button = QPushButton("Seçili Hesabı Sil")
        self.delete_button.clicked.connect(self.delete_account_gui)

        self.copy_pw_button = QPushButton("Seçili Şifreyi Kopyala")
        self.copy_pw_button.clicked.connect(self.copy_password)

        # **Master şifre değiştir butonu**
        self.change_master_button = QPushButton("Master Şifre Değiştir")
        self.change_master_button.clicked.connect(self.change_master_password)

        # Layout
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.service_input)
        input_layout.addWidget(self.username_input)
        input_layout.addWidget(self.add_button)

        layout = QVBoxLayout()
        layout.addLayout(input_layout)
        layout.addWidget(self.list_button)
        layout.addWidget(self.show_pw_checkbox)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.delete_button)
        btn_layout.addWidget(self.copy_pw_button)
        btn_layout.addWidget(self.change_master_button)  # buraya ekledik
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        # Stil aynı şekilde
        self.setStyleSheet("""
            QWidget { background-color: #2b2b2b; color: #eee; font-family: Arial; font-size:14px; }
            QPushButton { background-color: #4CAF50; color:white; border-radius:8px; padding:6px; font-weight:bold; }
            QPushButton:hover { background-color:#45a049; }
            QLineEdit { border:1px solid #555; border-radius:6px; padding:4px; background-color:#3c3c3c; color:#eee; }
            QTableWidget { background-color:#2b2b2b; color:#eee; gridline-color:#555; }
            QHeaderView::section { background-color:#3c3c3c; color:#fff; }
            QCheckBox { padding:4px; }
        """)
    def add_account_auto_password(self):
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        if not service or not username:
            QMessageBox.warning(self,"Eksik","Servis ve kullanıcı girilmeli!")
            return
        password = generate_strong_password().encode()
        encrypted = encrypt(password, self.master_password)
        add_account(service, username, encrypted)
        # Panoya kopyala
        QApplication.clipboard().setText(password.decode())
        QMessageBox.information(self,"Başarılı",f"Hesap eklendi ve şifre panoya kopyalandı!\nŞifre: {password.decode()}")
        self.load_accounts()

    def copy_password(self):
        row = self.table.currentRow()
        if row >=0:
            pw_item = self.table.item(row,2)
            if pw_item:
                pw = pw_item.text()
                # Şifre gizli ise decrypt yap
                if pw.startswith("*"):
                    service = self.table.item(row,0).text()
                    user = self.table.item(row,1).text()
                    accounts = list_accounts(service)
                    for s,u,enc_pw in accounts:
                        if u == user:
                            pw = decrypt(enc_pw, self.master_password)
                            break
                QApplication.clipboard().setText(pw)
                QMessageBox.information(self,"Kopyalandı","Şifre panoya kopyalandı!")
        else:
            QMessageBox.warning(self,"Hata","Bir hesap seçin.")

    def add_account_gui(self):
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        if not service or not username:
            QMessageBox.warning(self,"Eksik","Servis ve kullanıcı girilmeli!")
            return

        # Aynı servis + kullanıcı adı kontrolü
        existing = list_accounts(service)
        for s,u,enc_pw in existing:
            if u == username:
                QMessageBox.warning(self,"Hata","Bu servis ve kullanıcı adı zaten mevcut!")
                return

    # Hesap ekleme
        password = generate_strong_password().encode()
        encrypted = encrypt(password, self.master_password)
        add_account(service, username, encrypted)
        QMessageBox.information(self,"Başarılı","Hesap eklendi!")
        self.load_accounts()


    def ask_list_type(self):
        services = get_services()
        options = ["Tüm Hesaplar"] + services
        choice, ok = QInputDialog.getItem(self,"Listeleme","Hangi hesapları görmek istiyorsun?", options, 0, False)
        if ok:
            if choice == "Tüm Hesaplar":
                self.load_accounts()
            else:
                self.load_accounts(choice)

    def load_accounts(self, service=None):
        self.table.setRowCount(0)
        rows = list_accounts(service)
        for i, row in enumerate(rows):
            svc, user, enc_pw = row
            pw = decrypt(enc_pw, self.master_password)
            if not self.show_pw_checkbox.isChecked():
                pw = "*" * len(pw)
            self.table.insertRow(i)
            self.table.setItem(i,0,QTableWidgetItem(svc))
            self.table.setItem(i,1,QTableWidgetItem(user))
            self.table.setItem(i,2,QTableWidgetItem(pw))

    def delete_account_gui(self):
        row = self.table.currentRow()
        if row >=0:
            service = self.table.item(row,0).text()
            user = self.table.item(row,1).text()
            delete_account(service,user)
            QMessageBox.information(self,"Silindi",f"{service} - {user} silindi!")
            self.load_accounts()
        else:
            QMessageBox.warning(self,"Hata","Bir hesap seçin.")

    def toggle_password_visibility(self):
        self.load_accounts()  # checkbox değişince tabloyu yeniden yükle
    
    def change_master_password(self):
    # Pencereyi gösterecek QWidget
        dlg = QWidget()
        dlg.setWindowTitle("Master Şifre Değiştir")
        dlg.setGeometry(300, 300, 400, 200)

        layout = QVBoxLayout()

        # Mevcut şifre
        label_current = QLabel("Mevcut Master Şifre:")
        input_current = QLineEdit()
        input_current.setEchoMode(QLineEdit.EchoMode.Password)

        # Yeni şifre
        label_new = QLabel("Yeni Şifre:")
        input_new = QLineEdit()
        input_new.setEchoMode(QLineEdit.EchoMode.Password)

        # Yeni şifre tekrar
        label_new2 = QLabel("Yeni Şifre Tekrar:")
        input_new2 = QLineEdit()
        input_new2.setEchoMode(QLineEdit.EchoMode.Password)

        # Şifreyi göster checkbox
        show_pw_checkbox = QCheckBox("Şifreleri Göster")
        def toggle_pw():
            mode = QLineEdit.EchoMode.Normal if show_pw_checkbox.isChecked() else QLineEdit.EchoMode.Password
            input_current.setEchoMode(mode)
            input_new.setEchoMode(mode)
            input_new2.setEchoMode(mode)
        show_pw_checkbox.stateChanged.connect(toggle_pw)

        # Değiştir butonu
        button_change = QPushButton("Değiştir")
        def do_change():
            current_pw = input_current.text()
            new_pw = input_new.text()
            new_pw2 = input_new2.text()

            if current_pw != self.master_password:
                QMessageBox.warning(dlg, "Hata", "Mevcut şifre yanlış!")
                return
            if new_pw != new_pw2:
                QMessageBox.warning(dlg, "Hata", "Yeni şifreler uyuşmuyor!")
                return
            if len(new_pw) < 8:
                QMessageBox.warning(dlg,"Hata","Şifre en az 8 karakter olmalı!")
                return
            if not any(c.isupper() for c in new_pw):
                QMessageBox.warning(dlg,"Hata","Şifre en az bir büyük harf içermeli!")
                return
            if not any(c.isdigit() for c in new_pw):
                QMessageBox.warning(dlg,"Hata","Şifre en az bir rakam içermeli!")
                return
            if not any(c in string.punctuation for c in new_pw):
                QMessageBox.warning(dlg,"Hata","Şifre en az bir özel karakter içermeli!")
                return

            # Hesapları güncelle
            conn = sql.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM accounts")
            accounts = cursor.fetchall()
            for acc_id, enc_pw in accounts:
                decrypted = decrypt(enc_pw, self.master_password).encode()
                new_enc = encrypt(decrypted, new_pw)
                cursor.execute("UPDATE accounts SET password=? WHERE id=?", (new_enc, acc_id))

            cursor.execute("SELECT id FROM master_key LIMIT 1")
            master_id = cursor.fetchone()[0]
            salt = get_random_bytes(16)
            hash_pw = PBKDF2(new_pw, salt, dkLen=KEY_LEN, count=PBKDF2_ITERATIONS)
            cursor.execute("UPDATE master_key SET salt=?, hash=? WHERE id=?", (salt, hash_pw, master_id))
            conn.commit()
            conn.close()

            self.master_password = new_pw
            QMessageBox.information(dlg,"Başarılı","Master şifre değiştirildi ve tüm hesaplar güncellendi!")
            self.load_accounts()
            dlg.close()

        button_change.clicked.connect(do_change)

        layout.addWidget(label_current)
        layout.addWidget(input_current)
        layout.addWidget(label_new)
        layout.addWidget(input_new)
        layout.addWidget(label_new2)
        layout.addWidget(input_new2)
        layout.addWidget(show_pw_checkbox)
        layout.addWidget(button_change)

        dlg.setLayout(layout)
        dlg.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    init_db()
    conn = sql.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT * FROM master_key LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if row is None:
        win = MasterPasswordWindow()
        win.show()
    else:
        login = LoginWindow()
        login.show()
    sys.exit(app.exec())