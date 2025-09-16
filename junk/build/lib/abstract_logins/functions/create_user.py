#!/usr/bin/env python3
"""
create_user.py (updated to use Qt5 instead of PySimpleGUI)
"""
from .imports import *
from .auth_utils import upsert_admin
LOG_FILE_PATH = "user_creation.log"  # plaintext-audit log
def append_log(username: str, plaintext_password: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(LOG_FILE_PATH, "a", encoding="utf8") as f:
        f.write(f"[{ts}] {username} → {plaintext_password}\n")

class GetUserStore(metaclass=SingletonMeta):
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            from auth_utils import ensure_users_table_exists, get_user, add_or_update_user, verify_password, get_existing_users
            self.get_user = get_user
            self.add_or_update_user = add_or_update_user
            self.get_existing_users = get_existing_users
            self.ensure_users_table_exists = ensure_users_table_exists
            self.verify_password = verify_password

class AdminLoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Admin Authentication Required")
        self.setFixedSize(400, 200)
        self.user_store = GetUserStore()

        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Username
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        username_label.setFixedWidth(100)
        self.username_input = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)

        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        password_label.setFixedWidth(100)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)

        # Buttons
        button_layout = QHBoxLayout()
        login_button = QPushButton("Login")
        login_button.clicked.connect(self.handle_login)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.close)
        button_layout.addWidget(login_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        layout.addStretch()

    def handle_login(self):
        admin_user = self.username_input.text().strip()
        admin_pass = self.password_input.text()

        if not admin_user or not admin_pass:
            QMessageBox.critical(self, "Login Failed", "Both fields are required.")
            return

        row = self.user_store.get_user(admin_user)
        if not row:
            QMessageBox.critical(self, "Login Failed", "Admin user not found.")
            return

        if not row["is_admin"]:
            QMessageBox.critical(self, "Access Denied", "User is not an administrator.")
            return

        if not self.user_store.verify_password(admin_pass, row["password_hash"]):
            QMessageBox.critical(self, "Login Failed", "Incorrect password.")
            return

        self.admin_user = admin_user
        self.close()

class UserManagementWindow(QMainWindow):
    def __init__(self, admin_username: str):
        super().__init__()
        self.setWindowTitle("User Manager (Postgres via AbstractDB)")
        self.setFixedSize(500, 300)
        self.admin_username = admin_username
        self.user_store = GetUserStore()
        self.blinking = False
        self.blink_count = 0
        self.max_blinks = 6
        self.blink_timer = QTimer(self)

        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Admin label
        self.admin_label = QLabel(f"Logged in as admin: {admin_username}")
        layout.addWidget(self.admin_label)

        # User selection
        user_select_layout = QHBoxLayout()
        user_select_label = QLabel("Select User:")
        user_select_label.setFixedWidth(100)
        self.user_combo = QComboBox()
        existing_users = self.user_store.get_existing_users()
        self.user_combo.addItem("<New User>")
        self.user_combo.addItems(existing_users)
        self.user_combo.currentTextChanged.connect(self.on_user_select)
        user_select_layout.addWidget(user_select_label)
        user_select_layout.addWidget(self.user_combo)
        layout.addLayout(user_select_layout)

        # Username
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        username_label.setFixedWidth(100)
        self.username_input = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)

        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        password_label.setFixedWidth(100)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)

        # Admin checkbox
        self.admin_checkbox = QCheckBox("Admin User?")
        layout.addWidget(self.admin_checkbox)

        # Buttons
        button_layout = QHBoxLayout()
        self.random_password_button = QPushButton("Generate Password")
        self.random_password_button.clicked.connect(self.generate_password)
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.handle_ok)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.close)
        button_layout.addWidget(self.random_password_button)
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        layout.addStretch()

    def on_user_select(self, chosen):
        if chosen == "<New User>":
            self.username_input.setText("")
            self.password_input.setText("")
            self.admin_checkbox.setChecked(False)
        else:
            row = self.user_store.get_user(chosen)
            self.username_input.setText(chosen)
            self.password_input.setText("")
            self.admin_checkbox.setChecked(row["is_admin"] if row else False)

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            pwd = "".join(secrets.choice(alphabet) for _ in range(16))
            if (
                any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in string.punctuation for c in pwd)
            ):
                break
        self.password_input.setText(pwd)

    def handle_ok(self):
        user_input = self.username_input.text().strip()
        pwd_input = self.password_input.text()
        is_admin_flag = self.admin_checkbox.isChecked()

        if not user_input:
            self.start_blinking(self.username_input)
            return

        existing_row = self.user_store.get_user(user_input)
        if existing_row is None:
            # New user
            if not pwd_input:
                self.start_blinking(self.password_input)
                return

            self.user_store.add_or_update_user(
                username=user_input,
                plaintext_pwd=pwd_input,
                is_admin=is_admin_flag
            )
            append_log(user_input, pwd_input)
            QMessageBox.information(self, "Success", f"New user '{user_input}' created. Admin={is_admin_flag}")
            self.close()

        else:
            # Existing user
            if not pwd_input:
                self.user_store.add_or_update_user(
                    username=user_input,
                    plaintext_pwd=existing_row["password_hash"],
                    is_admin=is_admin_flag
                )
                QMessageBox.information(self, "Success", f"Updated user '{user_input}'. Admin={is_admin_flag}")
                self.close()
            else:
                self.user_store.add_or_update_user(
                    username=user_input,
                    plaintext_pwd=pwd_input,
                    is_admin=is_admin_flag
                )
                append_log(user_input, pwd_input)
                QMessageBox.information(self, "Success", f"User '{user_input}' updated. Admin={is_admin_flag}")
                self.close()

    def start_blinking(self, widget):
        self.blinking = True
        self.blink_count = 0
        self.blink_widget = widget
        self.blink_timer.timeout.connect(self.toggle_blink)
        self.blink_timer.start(300)

    def toggle_blink(self):
        if self.blink_count % 2 == 0:
            self.blink_widget.setStyleSheet("background-color: white;")
        else:
            self.blink_widget.setStyleSheet("background-color: red;")

        self.blink_count += 1
        if self.blink_count >= self.max_blinks:
            self.blink_timer.stop()
            self.blinking = False
            self.blink_widget.setStyleSheet("background-color: white;")

def edit_users():
    app = QApplication(sys.argv)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--init-db",
        action="store_true",
        help="Initialize the Postgres schema (create 'users' table) and exit."
    )
    args = parser.parse_args()

    if args.init_db:
        ensure_users_table_exists = GetUserStore().ensure_users_table_exists
        try:
            ensure_users_table_exists()
            print("✅ Schema initialized successfully (Postgres 'users' table created).")
        except Exception as e:
            print("✘ Error initializing schema:", e)
            sys.exit(1)
        sys.exit(0)

    admin_login = AdminLoginWindow()
    admin_login.show()
    app.exec_()

    if hasattr(admin_login, 'admin_user'):
        user_management = UserManagementWindow(admin_login.admin_user)
        user_management.show()
        app.exec_()
    else:
        print("✘ Administrator login failed or cancelled. Exiting.")
        sys.exit(1)

