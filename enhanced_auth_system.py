import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import os
import binascii
from hashlib import pbkdf2_hmac
import json
import datetime
import socket
import re
from typing import Optional
import threading
import time

class SecurityConfig:
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 minutes in seconds
    MIN_PASSWORD_LENGTH = 8
    PASSWORD_HISTORY_SIZE = 3
    SESSION_DURATION = 3600  # 1 hour in seconds

class ThemeConfig:
    DARK = {
        "bg": "#1a237e",           # Koyu mavi arka plan
        "fg": "#ffffff",           # Beyaz yazı
        "button": "#3949ab",       # Ana buton rengi
        "button_fg": "#ffffff",    # Buton yazı rengi
        "button_hover": "#5c6bc0", # Hover rengi
        "entry": "#283593",        # Giriş alanı
        "entry_fg": "#ffffff",     # Giriş yazı rengi
        "gradient_start": "#1a237e",
        "gradient_end": "#283593"
    }

    @staticmethod
    def get_button_style(theme):
        return {
            "background": theme["button"],
            "foreground": theme["button_fg"],
            "font": ("Arial", 11),
            "padding": 10,
            "width": 15,
            "cursor": "hand2"
        }

    @staticmethod
    def get_entry_style(theme):
        return {
            "background": theme["entry"],
            "foreground": theme["entry_fg"],
            "font": ("Arial", 11),
            "width": 30
        }

class DatabaseManager:
    def __init__(self):
        self.db_name = "enhanced_users.db"
        self.initialize_db()

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_name)
        return self.conn.cursor()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.conn.commit()
        self.conn.close()

    def initialize_db(self):
        with self as cursor:
            # Users table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                security_question TEXT NOT NULL,
                security_answer TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_ip TEXT,
                failed_attempts INTEGER DEFAULT 0,
                lockout_until TIMESTAMP,
                theme_preference TEXT DEFAULT 'light',
                language_preference TEXT DEFAULT 'tr'
            )
            """)

            # Password history table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)

            # Login history table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                success BOOLEAN,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)

            # Sessions table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> tuple:
        if salt is None:
            salt = os.urandom(16)
        else:
            salt = binascii.unhexlify(salt)
        
        key = pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        
        return binascii.hexlify(key).decode('ascii'), binascii.hexlify(salt).decode('ascii')

    @staticmethod
    def check_password_strength(password: str) -> tuple:
        """Check password strength and return (is_strong, message)"""
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            return False, "Şifre en az 8 karakter olmalıdır."
        
        checks = [
            (r"[A-Z]", "büyük harf"),
            (r"[a-z]", "küçük harf"),
            (r"[0-9]", "sayı"),
            (r"[!@#$%^&*(),.?\":{}|<>]", "özel karakter")
        ]
        
        missing = [desc for pattern, desc in checks if not re.search(pattern, password)]
        
        if missing:
            return False, f"Şifre {', '.join(missing)} içermelidir."
        
        return True, "Güçlü şifre"

    def is_account_locked(self, username: str) -> bool:
        with self as cursor:
            cursor.execute("""
            SELECT failed_attempts, lockout_until 
            FROM users 
            WHERE username = ?
            """, (username,))
            result = cursor.fetchone()
            
            if not result:
                return False
                
            failed_attempts, lockout_until = result
            
            if lockout_until and datetime.datetime.strptime(lockout_until, "%Y-%m-%d %H:%M:%S") > datetime.datetime.now():
                return True
                
            if failed_attempts >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
                lockout_time = datetime.datetime.now() + datetime.timedelta(seconds=SecurityConfig.LOCKOUT_DURATION)
                cursor.execute("""
                UPDATE users 
                SET lockout_until = ? 
                WHERE username = ?
                """, (lockout_time.strftime("%Y-%m-%d %H:%M:%S"), username))
                return True
                
            return False

    def register_user(self, username: str, password: str, email: str, security_question: str, security_answer: str) -> tuple:
        try:
            # Check password strength
            is_strong, message = self.check_password_strength(password)
            if not is_strong:
                return False, message

            # Hash password and security answer
            password_hash, salt = self.hash_password(password)
            answer_hash, answer_salt = self.hash_password(security_answer)
            
            with self as cursor:
                # Insert user
                cursor.execute("""
                INSERT INTO users 
                (username, password, salt, email, security_question, security_answer) 
                VALUES (?, ?, ?, ?, ?, ?)
                """, (username, password_hash, salt, email, security_question, answer_hash))
                
                user_id = cursor.lastrowid
                
                # Add to password history
                cursor.execute("""
                INSERT INTO password_history 
                (user_id, password, salt) 
                VALUES (?, ?, ?)
                """, (user_id, password_hash, salt))
            
            return True, "Kayıt başarılı"
        except sqlite3.IntegrityError:
            return False, "Bu kullanıcı adı veya email zaten kullanımda"
        except Exception as e:
            return False, f"Kayıt hatası: {str(e)}"

    def authenticate_user(self, username: str, password: str, ip_address: str) -> tuple:
        try:
            if self.is_account_locked(username):
                return False, "Hesap kilitli. Lütfen daha sonra tekrar deneyin."

            with self as cursor:
                cursor.execute("""
                SELECT id, password, salt, failed_attempts 
                FROM users 
                WHERE username = ?
                """, (username,))
                result = cursor.fetchone()
                
                if not result:
                    return False, "Kullanıcı bulunamadı"
                    
                user_id, stored_hash, salt, failed_attempts = result
                input_hash, _ = self.hash_password(password, salt)
                
                success = stored_hash == input_hash
                
                # Update login history
                cursor.execute("""
                INSERT INTO login_history 
                (user_id, ip_address, success) 
                VALUES (?, ?, ?)
                """, (user_id, ip_address, success))
                
                if success:
                    # Reset failed attempts and update last login
                    cursor.execute("""
                    UPDATE users 
                    SET failed_attempts = 0, 
                        last_login = CURRENT_TIMESTAMP, 
                        last_ip = ?,
                        lockout_until = NULL 
                    WHERE id = ?
                    """, (ip_address, user_id))
                    return True, user_id
                else:
                    # Increment failed attempts
                    new_attempts = failed_attempts + 1
                    cursor.execute("""
                    UPDATE users 
                    SET failed_attempts = ? 
                    WHERE id = ?
                    """, (new_attempts, user_id))
                    
                    remaining = SecurityConfig.MAX_LOGIN_ATTEMPTS - new_attempts
                    return False, f"Hatalı şifre. Kalan deneme: {remaining}"
                    
        except Exception as e:
            return False, f"Giriş hatası: {str(e)}"

class EnhancedAuthApp:
    def __init__(self, root):
        self.root = root
        self.db = DatabaseManager()
        
        # Kaydedilmiş tema tercihini yükle
        try:
            with open("theme_preference.txt", "r") as f:
                self.current_theme = f.read().strip()
                if self.current_theme not in ["light", "dark"]:
                    self.current_theme = "light"
        except:
            self.current_theme = "light"
        
        self.current_theme_colors = ThemeConfig.DARK if self.current_theme == "dark" else ThemeConfig.DARK
        self.setup_ui()
        
        self.security_questions = [
            "İlk evcil hayvanınızın adı nedir?",
            "Annenizin kızlık soyadı nedir?",
            "İlk okulunuzun adı nedir?",
            "Doğduğunuz şehir neresidir?",
            "En sevdiğiniz öğretmenin adı nedir?"
        ]

    def get_ip_address(self) -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"

    def setup_ui(self):
        # Önceki widget'ları temizle
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.title("Gelişmiş Kimlik Doğrulama Sistemi")
        self.root.geometry("500x700")
        self.root.resizable(False, False)
        self.root.configure(bg=ThemeConfig.DARK["bg"])

        # Logo ve başlık
        logo_frame = tk.Frame(self.root, bg=ThemeConfig.DARK["bg"])
        logo_frame.pack(pady=(30, 20))

        # Logo
        logo_label = tk.Label(
            logo_frame,
            text="🔐",
            font=("Segoe UI", 48),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        )
        logo_label.pack()

        # Başlık
        tk.Label(
            logo_frame,
            text="Güvenli Kimlik Doğrulama",
            font=("Segoe UI", 24, "bold"),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(pady=(10, 0))

        # Ana form container
        form_frame = tk.Frame(self.root, bg=ThemeConfig.DARK["bg"])
        form_frame.pack(padx=50, pady=20, fill="both", expand=True)

        # Giriş Yap başlığı
        tk.Label(
            form_frame,
            text="Giriş Yap",
            font=("Segoe UI", 18, "bold"),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(pady=(0, 20))

        # Kullanıcı adı
        tk.Label(
            form_frame,
            text="👤 Kullanıcı Adı",
            font=("Segoe UI", 12),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(anchor="w")

        self.username_entry = tk.Entry(
            form_frame,
            font=("Segoe UI", 12),
            bg=ThemeConfig.DARK["entry"],
            fg=ThemeConfig.DARK["entry_fg"],
            insertbackground=ThemeConfig.DARK["fg"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=ThemeConfig.DARK["button"],
            highlightcolor=ThemeConfig.DARK["button_hover"]
        )
        self.username_entry.pack(fill="x", pady=(5, 15))

        # Şifre
        tk.Label(
            form_frame,
            text="🔒 Şifre",
            font=("Segoe UI", 12),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(anchor="w")

        password_frame = tk.Frame(form_frame, bg=ThemeConfig.DARK["bg"])
        password_frame.pack(fill="x", pady=(5, 15))

        self.password_entry = tk.Entry(
            password_frame,
            font=("Segoe UI", 12),
            bg=ThemeConfig.DARK["entry"],
            fg=ThemeConfig.DARK["entry_fg"],
            insertbackground=ThemeConfig.DARK["fg"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=ThemeConfig.DARK["button"],
            highlightcolor=ThemeConfig.DARK["button_hover"],
            show="●"
        )
        self.password_entry.pack(side="left", fill="x", expand=True)

        # Şifre göster/gizle butonu
        self.show_password_btn = self.create_button(
            password_frame,
            text="👁",
            command=self.toggle_password_visibility,
            width=3
        )
        self.show_password_btn.pack(side="left", padx=(5, 0))

        # Beni hatırla
        remember_frame = tk.Frame(form_frame, bg=ThemeConfig.DARK["bg"])
        remember_frame.pack(fill="x", pady=(0, 20))

        self.remember_var = tk.BooleanVar()
        tk.Checkbutton(
            remember_frame,
            text="Beni Hatırla",
            variable=self.remember_var,
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"],
            activebackground=ThemeConfig.DARK["bg"],
            activeforeground=ThemeConfig.DARK["fg"],
            selectcolor=ThemeConfig.DARK["button"]
        ).pack(side="left")

        # Giriş butonu
        self.create_button(
            form_frame,
            text="Giriş Yap",
            command=self.login,
            font=("Segoe UI", 12, "bold")
        ).pack(fill="x", pady=(20, 30))

        # Alt butonlar
        button_frame = tk.Frame(form_frame, bg=ThemeConfig.DARK["bg"])
        button_frame.pack(fill="x")
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)

        self.create_button(
            button_frame,
            text="Yeni Hesap",
            command=self.show_register_window
        ).grid(row=0, column=0, padx=5, sticky="ew")

        self.create_button(
            button_frame,
            text="Şifremi Unuttum",
            command=self.show_reset_window
        ).grid(row=0, column=1, padx=5, sticky="ew")

    def create_button(self, parent, **kwargs):
        btn = tk.Button(
            parent,
            font=kwargs.pop("font", ("Segoe UI", 11)),
            bg=ThemeConfig.DARK["button"],
            fg=ThemeConfig.DARK["button_fg"],
            activebackground=ThemeConfig.DARK["button_hover"],
            activeforeground=ThemeConfig.DARK["button_fg"],
            relief="flat",
            cursor="hand2",
            **kwargs
        )
        
        # Hover efekti
        def on_enter(e):
            btn['background'] = ThemeConfig.DARK["button_hover"]
            
        def on_leave(e):
            btn['background'] = ThemeConfig.DARK["button"]
            
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        
        return btn

    def toggle_password_visibility(self):
        current = self.password_entry.cget("show")
        self.password_entry.config(show="" if current else "*")
        self.show_password_btn.config(text="👁" if current else "🔒")

    def toggle_theme(self):
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        self.current_theme_colors = ThemeConfig.DARK if self.current_theme == "dark" else ThemeConfig.DARK
        
        # Tüm arayüzü yeniden oluştur
        self.setup_ui()

        # Tema değişikliğini kaydet
        try:
            with open("theme_preference.txt", "w") as f:
                f.write(self.current_theme)
        except:
            pass  # Dosya yazılamadıysa önemli değil

    def apply_theme(self, theme_name):
        theme = ThemeConfig.DARK if theme_name == "dark" else ThemeConfig.DARK
        style = ttk.Style()

        # Ana stil ayarları
        style.configure("Main.TFrame", background=theme["bg"])
        style.configure("Banner.TFrame", background=theme["gradient_start"])
        style.configure("Content.TFrame", background=theme["bg"])
        style.configure("Form.TFrame", background=theme["bg"])
        style.configure("Field.TFrame", background=theme["bg"])
        style.configure("Bottom.TFrame", background=theme["bg"])

        # Etiket stilleri
        style.configure("Logo.TLabel",
            background=theme["gradient_start"],
            foreground="#ffffff"  # Logo her zaman beyaz
        )
        style.configure("BannerTitle.TLabel",
            background=theme["gradient_start"],
            foreground="#ffffff"  # Banner yazısı her zaman beyaz
        )
        style.configure("FormTitle.TLabel",
            background=theme["bg"],
            foreground=theme["fg"]
        )
        style.configure("FieldLabel.TLabel",
            background=theme["bg"],
            foreground=theme["fg"]
        )

        # Entry stili
        style.configure("Custom.TEntry",
            fieldbackground=theme["entry"],
            foreground=theme["entry_fg"]
        )

        # Buton stilleri
        button_style = {
            "background": theme["button"],
            "foreground": theme["button_fg"],
            "relief": "raised",
            "borderwidth": 1
        }

        style.configure("Primary.TButton",
            **button_style,
            font=("Segoe UI", 11, "bold")
        )
        style.configure("Action.TButton",
            **button_style,
            font=("Segoe UI", 10, "bold")
        )
        style.configure("Secondary.TButton",
            **button_style,
            font=("Segoe UI", 10)
        )
        style.configure("Theme.TButton",
            **button_style,
            font=("Segoe UI", 9, "bold")
        )
        style.configure("Icon.TButton",
            **button_style,
            font=("Segoe UI", 9)
        )

        # Hover efektleri
        hover_style = {
            "background": [("active", theme["hover"])],
            "foreground": [("active", theme["button_fg"])]
        }

        for button_type in ["Primary", "Action", "Secondary", "Theme", "Icon"]:
            style.map(f"{button_type}.TButton", **hover_style)

        # Checkbutton stili
        style.configure("Custom.TCheckbutton",
            background=theme["bg"],
            foreground=theme["fg"]
        )

        # Banner gradient
        banner_canvas = tk.Canvas(
            self.root,
            height=100,
            width=500,
            highlightthickness=0
        )
        banner_canvas.place(x=0, y=0)
        
        banner_canvas.create_rectangle(
            0, 0, 500, 100,
            fill=theme["gradient_start"],
            outline=theme["gradient_start"]
        )

        # Root window arka plan
        self.root.configure(bg=theme["bg"])

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Hata", "Kullanıcı adı ve şifre gereklidir!")
            return
        
        success, message = self.db.authenticate_user(
            username,
            password,
            self.get_ip_address()
        )
        
        if success:
            if isinstance(message, int):  # message contains user_id on success
                if self.remember_var.get():
                    self.create_session(message)
                self.show_dashboard(message)
            else:
                messagebox.showinfo("Başarılı", "Giriş başarılı!")
        else:
            messagebox.showerror("Hata", message)

    def create_session(self, user_id):
        session_token = binascii.hexlify(os.urandom(32)).decode('ascii')
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=SecurityConfig.SESSION_DURATION)
        
        with self.db as cursor:
            cursor.execute("""
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
            """, (user_id, session_token, expires_at.strftime("%Y-%m-%d %H:%M:%S")))

    def show_dashboard(self, user_id):
        # Yeni pencere oluştur
        dashboard = tk.Toplevel(self.root)
        dashboard.title("Kullanıcı Paneli")
        dashboard.geometry("600x400")
        
        # Kullanıcı bilgilerini getir
        with self.db as cursor:
            cursor.execute("""
            SELECT username, email, last_login, last_ip
            FROM users
            WHERE id = ?
            """, (user_id,))
            user_data = cursor.fetchone()
            
            if user_data:
                username, email, last_login, last_ip = user_data
                
                # Bilgileri göster
                info_frame = ttk.Frame(dashboard)
                info_frame.pack(pady=20, padx=20, fill="x")
                
                ttk.Label(
                    info_frame,
                    text=f"Hoş geldiniz, {username}!",
                    font=("Arial", 16, "bold")
                ).pack(anchor="w")
                
                ttk.Label(
                    info_frame,
                    text=f"Email: {email}"
                ).pack(anchor="w")
                
                if last_login:
                    ttk.Label(
                        info_frame,
                    text=f"Son giriş: {last_login}"
                    ).pack(anchor="w")
                
                if last_ip:
                    ttk.Label(
                        info_frame,
                        text=f"Son IP: {last_ip}"
                    ).pack(anchor="w")
                
                # Butonlar
                button_frame = ttk.Frame(dashboard)
                button_frame.pack(pady=20)
                
                ttk.Button(
                    button_frame,
                    text="Şifre Değiştir",
                    command=lambda: self.show_change_password_window(user_id)
                ).pack(pady=5)
                
                ttk.Button(
                    button_frame,
                    text="Giriş Geçmişi",
                    command=lambda: self.show_login_history(user_id)
                ).pack(pady=5)
                
                ttk.Button(
                    button_frame,
                    text="Hesabı Sil",
                    command=lambda: self.delete_account(user_id)
                ).pack(pady=5)

    def show_change_password_window(self, user_id):
        window = tk.Toplevel(self.root)
        window.title("Şifre Değiştir")
        window.geometry("400x300")
        
        ttk.Label(
            window,
            text="Mevcut Şifre:"
        ).pack(pady=(20, 5))
        
        current_password = ttk.Entry(window, show="*")
        current_password.pack()
        
        ttk.Label(
            window,
            text="Yeni Şifre:"
        ).pack(pady=(20, 5))
        
        new_password = ttk.Entry(window, show="*")
        new_password.pack()
        
        ttk.Label(
            window,
            text="Yeni Şifre (Tekrar):"
        ).pack(pady=(20, 5))
        
        new_password_confirm = ttk.Entry(window, show="*")
        new_password_confirm.pack()
        
        def change_password():
            if new_password.get() != new_password_confirm.get():
                messagebox.showerror("Hata", "Yeni şifreler eşleşmiyor!")
                return
                
            # Şifre değiştirme işlemi...
            
        ttk.Button(
            window,
            text="Şifre Değiştir",
            command=change_password
        ).pack(pady=20)

    def show_login_history(self, user_id):
        window = tk.Toplevel(self.root)
        window.title("Giriş Geçmişi")
        window.geometry("500x400")
        
        # Treeview oluştur
        columns = ("Tarih", "IP Adresi", "Durum")
        tree = ttk.Treeview(window, columns=columns, show="headings")
        
        # Kolonları yapılandır
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        # Verileri getir ve ekle
        with self.db as cursor:
            cursor.execute("""
            SELECT login_time, ip_address, success
            FROM login_history
            WHERE user_id = ?
            ORDER BY login_time DESC
            LIMIT 50
            """, (user_id,))
            
            for row in cursor.fetchall():
                login_time, ip, success = row
                status = "Başarılı" if success else "Başarısız"
                tree.insert("", "end", values=(login_time, ip, status))
        
        tree.pack(pady=20, padx=20, fill="both", expand=True)

    def delete_account(self, user_id):
        if messagebox.askyesno("Onay", "Hesabınızı silmek istediğinizden emin misiniz?"):
            with self.db as cursor:
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                cursor.execute("DELETE FROM login_history WHERE user_id = ?", (user_id,))
                cursor.execute("DELETE FROM password_history WHERE user_id = ?", (user_id,))
                cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            
            messagebox.showinfo("Başarılı", "Hesabınız başarıyla silindi.")
            self.root.quit()

    def show_register_window(self):
        register_window = tk.Toplevel(self.root)
        register_window.title("Yeni Hesap Oluştur")
        register_window.geometry("500x600")
        register_window.configure(bg=ThemeConfig.DARK["bg"])
        register_window.resizable(False, False)
        
        # Logo ve başlık
        tk.Label(
            register_window,
            text="🔐",
            font=("Segoe UI", 36),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(pady=(20, 0))

        tk.Label(
            register_window,
            text="Yeni Hesap Oluştur",
            font=("Segoe UI", 20, "bold"),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(pady=(10, 30))

        # Form container
        form_frame = tk.Frame(register_window, bg=ThemeConfig.DARK["bg"])
        form_frame.pack(padx=50, fill="both", expand=True)

        # Kullanıcı adı
        tk.Label(
            form_frame,
            text="👤 Kullanıcı Adı:",
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(anchor="w")

        username_entry = tk.Entry(
            form_frame,
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["entry"],
            fg=ThemeConfig.DARK["entry_fg"],
            insertbackground=ThemeConfig.DARK["fg"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=ThemeConfig.DARK["button"],
            highlightcolor=ThemeConfig.DARK["button_hover"]
        )
        username_entry.pack(fill="x", pady=(5, 15))

        # Email
        tk.Label(
            form_frame,
            text="📧 Email:",
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(anchor="w")

        email_entry = tk.Entry(
            form_frame,
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["entry"],
            fg=ThemeConfig.DARK["entry_fg"],
            insertbackground=ThemeConfig.DARK["fg"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=ThemeConfig.DARK["button"],
            highlightcolor=ThemeConfig.DARK["button_hover"]
        )
        email_entry.pack(fill="x", pady=(5, 15))

        # Şifre
        tk.Label(
            form_frame,
            text="🔒 Şifre:",
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(anchor="w")

        password_frame = tk.Frame(form_frame, bg=ThemeConfig.DARK["bg"])
        password_frame.pack(fill="x", pady=(5, 15))

        password_entry = tk.Entry(
            password_frame,
            font=("Segoe UI", 11),
            show="●",
            bg=ThemeConfig.DARK["entry"],
            fg=ThemeConfig.DARK["entry_fg"],
            insertbackground=ThemeConfig.DARK["fg"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=ThemeConfig.DARK["button"],
            highlightcolor=ThemeConfig.DARK["button_hover"]
        )
        password_entry.pack(side="left", fill="x", expand=True)

        show_pass_btn = self.create_button(
            password_frame,
            text="👁",
            command=lambda: self.toggle_entry_visibility(password_entry),
            width=3
        )
        show_pass_btn.pack(side="left", padx=(5, 0))

        # Güvenlik sorusu
        tk.Label(
            form_frame,
            text="🔑 Güvenlik Sorusu:",
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(anchor="w", pady=(0, 5))

        security_question = ttk.Combobox(
            form_frame,
            values=self.security_questions,
            font=("Segoe UI", 11),
            state="readonly"
        )
        security_question.pack(fill="x")
        security_question.set(self.security_questions[0])

        # Güvenlik sorusu cevabı
        tk.Label(
            form_frame,
            text="🗝 Güvenlik Sorusu Cevabı:",
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["bg"],
            fg=ThemeConfig.DARK["fg"]
        ).pack(anchor="w", pady=(15, 5))

        answer_entry = tk.Entry(
            form_frame,
            font=("Segoe UI", 11),
            bg=ThemeConfig.DARK["entry"],
            fg=ThemeConfig.DARK["entry_fg"],
            insertbackground=ThemeConfig.DARK["fg"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=ThemeConfig.DARK["button"],
            highlightcolor=ThemeConfig.DARK["button_hover"]
        )
        answer_entry.pack(fill="x", pady=(5, 20))

        def register():
            # Tüm alanları kontrol et
            if not all([
                username_entry.get().strip(),
                email_entry.get().strip(),
                password_entry.get().strip(),
                security_question.get().strip(),
                answer_entry.get().strip()
            ]):
                messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
                return

            # Email formatını kontrol et
            email = email_entry.get().strip()
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                messagebox.showerror("Hata", "Geçersiz email formatı!")
                return

            # Şifre gücünü kontrol et
            password = password_entry.get().strip()
            is_strong, message = self.db.check_password_strength(password)
            if not is_strong:
                messagebox.showerror("Hata", message)
                return

            # Kullanıcıyı kaydet
            success, message = self.db.register_user(
                username_entry.get().strip(),
                password,
                email,
                security_question.get().strip(),
                answer_entry.get().strip()
            )

            if success:
                messagebox.showinfo("Başarılı", message)
                register_window.destroy()
            else:
                messagebox.showerror("Hata", message)

        # Kayıt butonu
        self.create_button(
            form_frame,
            text="Hesap Oluştur",
            command=register,
            font=("Segoe UI", 12, "bold")
        ).pack(fill="x", pady=(0, 30))

    def toggle_entry_visibility(self, entry_widget):
        current = entry_widget.cget("show")
        entry_widget.config(show="" if current else "●")

    def show_reset_window(self):
        reset_window = tk.Toplevel(self.root)
        reset_window.title("Şifre Sıfırlama")
        reset_window.geometry("400x500")
        reset_window.resizable(False, False)
        
        # Ana frame
        main_frame = ttk.Frame(reset_window)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Başlık
        ttk.Label(
            main_frame,
            text="Şifre Sıfırlama",
            font=("Arial", 20, "bold")
        ).pack(pady=20)
        
        # Kullanıcı adı
        ttk.Label(
            main_frame,
            text="Kullanıcı Adı:"
        ).pack()
        username_entry = ttk.Entry(main_frame, width=30)
        username_entry.pack(pady=(0, 10))
        
        # Güvenlik sorusu gösterme alanı
        question_var = tk.StringVar(value="")
        question_label = ttk.Label(
            main_frame,
            textvariable=question_var,
            wraplength=300
        )
        question_label.pack(pady=10)
        
        # Güvenlik sorusu cevabı
        answer_frame = ttk.Frame(main_frame)
        answer_frame.pack(pady=10, fill="x")
        
        ttk.Label(
            answer_frame,
            text="Cevap:"
        ).pack()
        answer_entry = ttk.Entry(answer_frame, width=30)
        answer_entry.pack(pady=5)
        answer_entry.config(state="disabled")
        
        # Yeni şifre alanları
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(pady=10, fill="x")
        
        ttk.Label(
            password_frame,
            text="Yeni Şifre:"
        ).pack()
        new_password = ttk.Entry(password_frame, width=30, show="*")
        new_password.pack(pady=5)
        new_password.config(state="disabled")
        
        def show_security_question():
            username = username_entry.get().strip()
            if not username:
                messagebox.showerror("Hata", "Lütfen kullanıcı adı girin!")
                return
            
            with self.db as cursor:
                cursor.execute("""
                SELECT security_question 
                FROM users 
                WHERE username = ?
                """, (username,))
                result = cursor.fetchone()
                
                if result:
                    question_var.set(f"Güvenlik Sorusu:\n{result[0]}")
                    answer_entry.config(state="normal")
                else:
                    messagebox.showerror("Hata", "Kullanıcı bulunamadı!")
        
        def verify_answer():
            username = username_entry.get().strip()
            answer = answer_entry.get().strip()
            
            if not answer:
                messagebox.showerror("Hata", "Lütfen güvenlik sorusu cevabını girin!")
                return
            
            with self.db as cursor:
                cursor.execute("""
                SELECT security_answer, salt 
                FROM users 
                WHERE username = ?
                """, (username,))
                result = cursor.fetchone()
                
                if result:
                    stored_answer, salt = result
                    input_answer, _ = self.db.hash_password(answer, salt)
                    
                    if stored_answer == input_answer:
                        new_password.config(state="normal")
                        reset_btn.config(state="normal")
                    else:
                        messagebox.showerror("Hata", "Yanlış cevap!")
        
        def reset_password():
            new_pass = new_password.get().strip()
            if not new_pass:
                messagebox.showerror("Hata", "Lütfen yeni şifre girin!")
                return
            
            # Şifre gücünü kontrol et
            is_strong, message = self.db.check_password_strength(new_pass)
            if not is_strong:
                messagebox.showerror("Hata", message)
                return
            
            username = username_entry.get().strip()
            answer = answer_entry.get().strip()
            
            with self.db as cursor:
                # Şifre geçmişini kontrol et
                cursor.execute("""
                SELECT u.id, ph.password, ph.salt
                FROM users u
                LEFT JOIN password_history ph ON u.id = ph.user_id
                WHERE u.username = ?
                ORDER BY ph.created_at DESC
                LIMIT ?
                """, (username, SecurityConfig.PASSWORD_HISTORY_SIZE))
                
                results = cursor.fetchall()
                if results:
                    user_id = results[0][0]
                    for _, old_password, old_salt in results:
                        if old_password:
                            new_hash, _ = self.db.hash_password(new_pass, old_salt)
                            if new_hash == old_password:
                                messagebox.showerror(
                                    "Hata",
                                    f"Bu şifre son {SecurityConfig.PASSWORD_HISTORY_SIZE} şifrenizden biri! Lütfen farklı bir şifre seçin."
                                )
                                return
                    
                    # Yeni şifreyi kaydet
                    new_hash, new_salt = self.db.hash_password(new_pass)
                    cursor.execute("""
                    UPDATE users 
                    SET password = ?, salt = ? 
                    WHERE id = ?
                    """, (new_hash, new_salt, user_id))
                    
                    # Şifre geçmişine ekle
                    cursor.execute("""
                    INSERT INTO password_history (user_id, password, salt)
                    VALUES (?, ?, ?)
                    """, (user_id, new_hash, new_salt))
                    
                    messagebox.showinfo("Başarılı", "Şifreniz başarıyla değiştirildi!")
                    reset_window.destroy()
        
        # Butonlar
        ttk.Button(
            main_frame,
            text="Güvenlik Sorusunu Göster",
            command=show_security_question
        ).pack(pady=10)
        
        ttk.Button(
            main_frame,
            text="Cevabı Doğrula",
            command=verify_answer
        ).pack(pady=5)
        
        reset_btn = ttk.Button(
            main_frame,
            text="Şifreyi Sıfırla",
            command=reset_password,
            state="disabled"
        )
        reset_btn.pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedAuthApp(root)
    root.mainloop() 