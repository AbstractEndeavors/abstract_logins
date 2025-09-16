#!/usr/bin/env python3
"""
create_user.py (converted to PyQt5, using user_store.py + abstract database modules)
"""
from abstract_utilities import SingletonMeta
from pathlib import Path
from dotenv import load_dotenv
import os, argparse, time, sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox, QMessageBox)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QColor

LOG_FILE_PATH = "user_creation.log"

def append_log(username: str, plaintext_password: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(LOG_FILE_PATH, "a", encoding="utf8") as f:
        f.write(f"[{ts}] {username} → {plaintext_password}\n")

class get_user_store(metaclass=SingletonMeta):
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            from .. import ensure_users_table_exists, get_user, add_or_update_user, get_existing_users
            from ...login_utils import verify_password
            self.get_user = get_user
            self.add_or_update_user = add_or_update_user
            self.get_existing_users = get_existing_users
            self.ensure_users_table_exists = ensure_users_table_exists
            self.verify_password = verify_password

class AdminLoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.userStore_mgr = get_user_store()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Admin Authentication Required")
        self.setFixedSize(400, 200)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        title = QLabel("Administrator Login")
        title.setStyleSheet("font-size: 14pt;")
        layout.addWidget(title)

        user_layout = QHBoxLayout()
        user_label = QLabel("Username:")
        user_label.setFixedWidth(80)
        self.user_input = QLineEdit()
        user_layout.addWidget(user_label)
        user_layout.addWidget(self.user_input)
        layout.addLayout(user_layout)

        pass_layout = QHBoxLayout()
        pass_label = QLabel("Password:")
        pass_label.setFixedWidth(80)
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(pass_label)
        pass_layout.addWidget(self.pass_input)
        layout.addLayout(pass_layout)

        button_layout = QHBoxLayout()
        login_btn = QPushButton("Login")
        cancel_btn = QPushButton("Cancel")
        login_btn.clicked.connect(self.handle_login)
        cancel_btn.clicked.connect(self.close)
        button_layout.addWidget(login_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        layout.addStretch()
        self.result = None

    def handle_login(self):
        admin_user = self.user_input.text().strip()
        admin_pass = self.pass_input.text()

        if not admin_user or not admin_pass:
            QMessageBox.critical(self, "Login Failed", "Both fields are required.")
            return

        row = self.userStore_mgr.get_user(admin_user)
        if not row:
            QMessageBox.critical(self, "Login Failed", "Admin user not found.")
            return

        if not row["is_admin"]:
            QMessageBox.critical(self, "Access Denied", "User is not an administrator.")
            return

        if not self.userStore_mgr.verify_password(admin_pass, row["password_hash"]):
            QMessageBox.critical(self, "Login Failed", "Incorrect password.")
            return

        self.result = admin_user
        self.close()

def admin_login_prompt():
    app = QApplication(sys.argv)
    window = AdminLoginWindow()
    window.show()
    app.exec_()
    return window.result

class UserManagementWindow(QMainWindow):
    def __init__(self, admin_username):
        super().__init__()
        self.admin_username = admin_username
        self.userStore_mgr = get_user_store()
        self.blinking = False
        self.blink_count = 0
        self.max_blinks = 6
        self.initUI()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.handle_blink)
        self.normal_color = self.user_input.palette().color(self.user_input.backgroundRole())
        self.error_color = QColor("red")

    def initUI(self):
        self.setWindowTitle("User Manager (Postgres via AbstractDB)")
        self.setFixedSize(500, 300)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        admin_label = QLabel(f"Logged in as admin: {self.admin_username}")
        admin_label.setStyleSheet("font-size: 12pt;")
        layout.addWidget(admin_label)

        user_select_layout = QHBoxLayout()
        user_select_label = QLabel("Select User:")
        self.user_select = QComboBox()
        existing_users = self.userStore_mgr.get_existing_users()
        self.user_select.addItem("<New User>")
        self.user_select.addItems(existing_users)
        self.user_select.currentTextChanged.connect(self.handle_user_select)
        user_select_layout.addWidget(user_select_label)
        user_select_layout.addWidget(self.user_select)
        layout.addLayout(user_select_layout)

        user_layout = QHBoxLayout()
        user_label = QLabel("Username:")
        user_label.setFixedWidth(80)
        self.user_input = QLineEdit()
        user_layout.addWidget(user_label)
        user_layout.addWidget(self.user_input)
        layout.addLayout(user_layout)

        pass_layout = QHBoxLayout()
        pass_label = QLabel("Password:")
        pass_label.setFixedWidth(80)
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(pass_label)
        pass_layout.addWidget(self.pass_input)
        layout.addLayout(pass_layout)

        admin_check = QCheckBox("Admin User?")
        self.admin_check = admin_check
        layout.addWidget(admin_check)

        button_layout = QHBoxLayout()
        random_btn = QPushButton("Generate Password")
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Cancel")
        random_btn.clicked.connect(self.generate_password)
        ok_btn.clicked.connect(self.handle_ok)
        cancel_btn.clicked.connect(self.close)
        button_layout.addWidget(random_btn)
        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        layout.addStretch()

    def handle_user_select(self, chosen):
        if chosen == "<New User>":
            self.user_input.setText("")
            self.pass_input.setText("")
            self.admin_check.setChecked(False)
        else:
            row = self.userStore_mgr.get_user(chosen)
            self.user_input.setText(chosen)
            self.pass_input.setText("")
            self.admin_check.setChecked(row["is_admin"] if row else False)

    def generate_password(self):
        import secrets, string
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            pwd = "".join(secrets.choice(alphabet) for _ in range(16))
            if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) and 
                any(c.isdigit() for c in pwd) and any(c in string.punctuation for c in pwd)):
                break
        self.pass_input.setText(pwd)

    def handle_blink(self):
        if self.blink_count % 2 == 0:
            self.user_input.setStyleSheet("background-color: white;")
            self.pass_input.setStyleSheet("background-color: white;")
        else:
            self.user_input.setStyleSheet("background-color: red;")
            self.pass_input.setStyleSheet("background-color: red;")
        self.blink_count += 1
        if self.blink_count >= self.max_blinks:
            self.timer.stop()
            self.blinking = False
            self.user_input.setStyleSheet("")
            self.pass_input.setStyleSheet("")

    def handle_ok(self):
        user_input = self.user_input.text().strip()
        pwd_input = self.pass_input.text()
        is_admin_flag = self.admin_check.isChecked()

        if not user_input:
            self.blinking = True
            self.blink_count = 0
            self.user_input.setStyleSheet("background-color: red;")
            self.timer.start(300)
            return

        existing_row = self.userStore_mgr.get_user(user_input)
        if existing_row is None:
            if not pwd_input:
                self.blinking = True
                self.blink_count = 0
                self.pass_input.setStyleSheet("background-color: red;")
                self.timer.start(300)
                return

            self.userStore_mgr.add_or_update_user(username=user_input, plaintext_pwd=pwd_input, is_admin=is_admin_flag)
            append_log(user_input, pwd_input)
            QMessageBox.information(self, "Success", f"New user '{user_input}' created. Admin={is_admin_flag}")
            self.close()
        else:
            if not pwd_input:
                self.userStore_mgr.add_or_update_user(username=user_input, plaintext_pwd=existing_row["password_hash"], is_admin=is_admin_flag)
                QMessageBox.information(self, "Success", f"Updated user '{user_input}'. Admin={is_admin_flag}")
                self.close()
            else:
                self.userStore_mgr.add_or_update_user(username=user_input, plaintext_pwd=pwd_input, is_admin=is_admin_flag)
                append_log(user_input, pwd_input)
                QMessageBox.information(self, "Success", f"User '{user_input}' updated. Admin={is_admin_flag}")
                self.close()

def edit_users():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--init-db",
        action="store_true",
        help="Initialize the Postgres schema (create 'users' table) and exit."
    )
    args = parser.parse_args()

    if args.init_db:
        ensure_users_table_exists = get_user_store().ensure_users_table_exists
        try:
            ensure_users_table_exists()
            print("✅ Schema initialized successfully (Postgres 'users' table created).")
        except Exception as e:
            print("✘ Error initializing schema:", e)
            sys.exit(1)
        sys.exit(0)

    admin_user = admin_login_prompt()
    if not admin_user:
        print("✘ Administrator login failed or cancelled. Exiting.")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = UserManagementWindow(admin_user)
    window.show()
    app.exec_()


