import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import time
import random
import json
import os
from datetime import datetime
import pyperclip

# Import our crypto libraries
import base64
import hashlib
import secrets
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import argon2

# Set the appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class ObscuraCrypto:
    """🔐 OBSCURA CRYPTO ENGINE"""
    
    def __init__(self):
        self.backend = default_backend()
        self.password_hasher = argon2.PasswordHasher(
            time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16
        )
        
    def generate_salt(self, length: int = 32) -> bytes:
        return secrets.token_bytes(length)
    
    def derive_key(self, password: str, salt: bytes, iterations: int = 100000) -> bytes:
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=iterations, backend=self.backend
        )
        return kdf.derive(password_bytes)
    
    def hash_password(self, password: str) -> str:
        return self.password_hasher.hash(password)
    
    def verify_password(self, password: str, hashed: str) -> bool:
        try:
            self.password_hasher.verify(hashed, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
    
    def encrypt_data(self, data: str, password: str) -> dict:
        plaintext = data.encode('utf-8')
        salt = self.generate_salt(32)
        nonce = self.generate_salt(12)
        key = self.derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        auth_tag = encryptor.tag
        
        key = b'\x00' * len(key)  # Clear key from memory
        
        return {
            'version': '1.0',
            'algorithm': 'AES-256-GCM',
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'timestamp': datetime.now().isoformat()
        }
    
    def decrypt_data(self, encrypted_package: dict, password: str) -> str:
        salt = base64.b64decode(encrypted_package['salt'])
        nonce = base64.b64decode(encrypted_package['nonce'])
        auth_tag = base64.b64decode(encrypted_package['auth_tag'])
        ciphertext = base64.b64decode(encrypted_package['ciphertext'])
        
        key = self.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, auth_tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            key = b'\x00' * len(key)  # Clear key from memory
            return plaintext.decode('utf-8')
        except Exception as e:
            key = b'\x00' * len(key)  # Clear key from memory
            raise Exception("🚨 DECRYPTION FAILED - Invalid password or corrupted data")

class ObscuraVaultManager:
    """🗄️ SECURE VAULT MANAGER"""
    
    def __init__(self, data_dir: str = ".obscura"):
        self.data_dir = data_dir
        self.crypto = ObscuraCrypto()
        self.vault_path = os.path.join(data_dir, "vault.enc")
        self.config_path = os.path.join(data_dir, "config.json")
        self.master_password_hash = None
        self.is_unlocked = False
        
        os.makedirs(data_dir, exist_ok=True)
        self._load_config()
    
    def _load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    self.master_password_hash = config.get('master_password_hash')
            except Exception:
                pass
    
    def _save_config(self):
        config = {
            'created': datetime.now().isoformat(),
            'master_password_hash': self.master_password_hash,
            'version': '2.0'
        }
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def is_vault_initialized(self) -> bool:
        return self.master_password_hash is not None
    
    def initialize_vault(self, master_password: str) -> bool:
        if self.is_vault_initialized():
            return False
        
        try:
            self.master_password_hash = self.crypto.hash_password(master_password)
            
            empty_vault = {
                'entries': [],
                'metadata': {
                    'created': datetime.now().isoformat(),
                    'version': '2.0',
                    'total_entries': 0
                }
            }
            
            encrypted_vault = self.crypto.encrypt_data(
                json.dumps(empty_vault, indent=2), master_password
            )
            
            with open(self.vault_path, 'w') as f:
                json.dump(encrypted_vault, f, indent=2)
            
            self._save_config()
            self.is_unlocked = True
            self._current_password = master_password
            return True
        except Exception:
            return False
    
    def unlock_vault(self, master_password: str) -> bool:
        if not self.is_vault_initialized():
            return False
        
        if not self.crypto.verify_password(master_password, self.master_password_hash):
            return False
        
        try:
            with open(self.vault_path, 'r') as f:
                encrypted_vault = json.load(f)
            
            self.crypto.decrypt_data(encrypted_vault, master_password)
            self.is_unlocked = True
            self._current_password = master_password
            return True
        except:
            return False
    
    def lock_vault(self):
        self.is_unlocked = False
        if hasattr(self, '_current_password'):
            self._current_password = '\x00' * len(self._current_password)
            delattr(self, '_current_password')
    
    def _load_vault_data(self) -> dict:
        if not self.is_unlocked:
            raise Exception("Vault is locked!")
        
        with open(self.vault_path, 'r') as f:
            encrypted_vault = json.load(f)
        
        decrypted_data = self.crypto.decrypt_data(encrypted_vault, self._current_password)
        return json.loads(decrypted_data)
    
    def _save_vault_data(self, vault_data: dict):
        if not self.is_unlocked:
            raise Exception("Vault is locked!")
        
        vault_data['metadata']['modified'] = datetime.now().isoformat()
        vault_data['metadata']['total_entries'] = len(vault_data['entries'])
        
        encrypted_vault = self.crypto.encrypt_data(
            json.dumps(vault_data, indent=2), self._current_password
        )
        
        with open(self.vault_path, 'w') as f:
            json.dump(encrypted_vault, f, indent=2)
    
    def add_entry(self, name: str, entry_type: str, data: dict, category: str = "Other", description: str = "") -> bool:
        try:
            vault_data = self._load_vault_data()
            
            for existing_entry in vault_data['entries']:
                if existing_entry['name'].lower() == name.lower():
                    return False
            
            new_entry = {
                'id': secrets.token_hex(8),
                'name': name,
                'type': entry_type,
                'data': data,
                'category': category,
                'description': description,
                'created': datetime.now().isoformat(),
                'last_used': 'Never',
                'usage_count': 0
            }
            
            vault_data['entries'].append(new_entry)
            self._save_vault_data(vault_data)
            return True
        except Exception:
            return False
    
    def list_entries(self) -> list:
        try:
            vault_data = self._load_vault_data()
            return vault_data.get('entries', [])
        except Exception:
            return []
    
    def get_entry_data(self, entry_id: str, field: str = None) -> str:
        try:
            vault_data = self._load_vault_data()
            
            for entry in vault_data['entries']:
                if entry['id'] == entry_id:
                    entry['last_used'] = datetime.now().strftime("%Y-%m-%d %H:%M")
                    entry['usage_count'] += 1
                    self._save_vault_data(vault_data)
                    
                    if field:
                        return entry['data'].get(field, '')
                    else:
                        if entry['type'] == 'api_key':
                            return entry['data'].get('key', '')
                        elif entry['type'] == 'password':
                            return entry['data'].get('password', '')
                        else:
                            return json.dumps(entry['data'])
            return None
        except Exception:
            return None
    
    def update_entry(self, entry_id: str, name: str, entry_type: str, data: dict, category: str, description: str) -> bool:
        try:
            vault_data = self._load_vault_data()
            
            for entry in vault_data['entries']:
                if entry['id'] == entry_id:
                    entry['name'] = name
                    entry['type'] = entry_type
                    entry['data'] = data
                    entry['category'] = category
                    entry['description'] = description
                    self._save_vault_data(vault_data)
                    return True
            return False
        except Exception:
            return False
    
    def delete_entry(self, entry_id: str) -> bool:
        try:
            vault_data = self._load_vault_data()
            vault_data['entries'] = [e for e in vault_data['entries'] if e['id'] != entry_id]
            self._save_vault_data(vault_data)
            return True
        except Exception:
            return False

class MatrixBackground:
    def __init__(self, parent, width=10000, height=10000):
        self.parent = parent
        self.width = width
        self.height = height
        self.canvas = tk.Canvas(parent, width=width, height=height, bg='#000011', highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?"
        self.drops = []
        self.cols =  120  # More columns for fuller coverage
        
        for i in range(self.cols):
            self.drops.append({
                'x': i * 15,
                'y': random.randint(-height, 0),
                'speed': random.randint(1, 6),
                'chars': [random.choice(self.chars) for _ in range(40)]  # More characters per drop
            })
        
        self.animate()
    
    def animate(self):
        self.canvas.delete("matrix")
        
        for drop in self.drops:
            for i, char in enumerate(drop['chars']):
                y_pos = drop['y'] + (i * 15)
                if -20 <= y_pos <= self.height + 20:  # Extended range for smoother effect
                    alpha = max(20, 255 - (i * 8))  # Better fade calculation
                    color = f"#{0:02x}{alpha:02x}{0:02x}"
                    
                    self.canvas.create_text(
                        drop['x'], y_pos, text=char, fill=color,
                        font=("Courier", 10, "bold"), tags="matrix"
                    )
            
            drop['y'] += drop['speed']
            if drop['y'] > self.height + 200:
                drop['y'] = random.randint(-200, -50)
                drop['speed'] = random.randint(1, 6)
                drop['chars'] = [random.choice(self.chars) for _ in range(40)]
        
        self.parent.after(80, self.animate)  # Slightly faster animation

class ObscuraAuth:
    def __init__(self, master, vault_manager):
        self.master = master
        self.vault_manager = vault_manager
        self.authenticated = False
        
        self.master.title("OBSCURA - Secure Access Terminal")
        self.master.geometry("1000x700")
        self.master.configure(bg='#000011')
        self.master.resizable(False, False)
        
        self.center_window()
        self.matrix_bg = MatrixBackground(self.master, 1000, 700)
        self.setup_ui()
        
    def center_window(self):
        self.master.update_idletasks()
        width = self.master.winfo_width()
        height = self.master.winfo_height()
        x = (self.master.winfo_screenwidth() // 2) - (width // 2)
        y = (self.master.winfo_screenheight() // 2) - (height // 2)
        self.master.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        self.main_frame = ctk.CTkFrame(
            self.master, width=400, height=500,
            fg_color="#0a0a0a", corner_radius=15,
            border_width=2, border_color="#00ff41"
        )
        self.main_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        self.title_label = ctk.CTkLabel(
            self.main_frame, text="◉ OBSCURA VAULT ◉",
            font=ctk.CTkFont(family="Courier New", size=28, weight="bold"),
            text_color="#00ff41"
        )
        self.title_label.pack(pady=(30, 10))
        
        if self.vault_manager.is_vault_initialized():
            self.setup_login_ui()
        else:
            self.setup_init_ui()
    
    def setup_login_ui(self):
        # Personal welcome message
        self.welcome_label = ctk.CTkLabel(
            self.main_frame, text="Welcome Back, Hammad Malik",
            font=ctk.CTkFont(family="Courier New", size=16, weight="bold"),
            text_color="#00ff41"  # Obsidian purple
        )
        self.welcome_label.pack(pady=(0, 10))
        
        self.subtitle_label = ctk.CTkLabel(
            self.main_frame, text="🔓 ENTER MASTER PASSWORD",
            font=ctk.CTkFont(family="Courier New", size=14),
            text_color="#888888"
        )
        self.subtitle_label.pack(pady=(0, 30))
        
        # Password entry with proper spacing
        self.password_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.password_frame.pack(pady=20, padx=30)  # Added padding from edges
        
        self.password_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(
            self.password_frame, width=300, height=40, show="●",
            font=ctk.CTkFont(family="Courier New", size=14),
            placeholder_text="Master Password", textvariable=self.password_var,
            corner_radius=10, border_width=2, border_color="#9571dd"  # Obsidian purple border
        )
        self.password_entry.pack(pady=10)  # Space from container
        self.password_entry.bind('<Return>', self.authenticate)
        
        self.login_btn = ctk.CTkButton(
            self.main_frame, text=">> UNLOCK VAULT <<", width=300, height=40,
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            command=self.authenticate, fg_color="#9571dd", hover_color="#c5aff3", text_color="#000000"
        )
        self.login_btn.pack(pady=20)
        
        self.password_entry.focus()
    
    def setup_init_ui(self):
        # Personal welcome for new vault
        self.welcome_label = ctk.CTkLabel(
            self.main_frame, text="Welcome, Hammad Malik",
            font=ctk.CTkFont(family="Courier New", size=16, weight="bold"),
            text_color="#c5aff3"  # Obsidian purple
        )
        self.welcome_label.pack(pady=(0, 10))
        
        self.subtitle_label = ctk.CTkLabel(
            self.main_frame, text="🔐 CREATE NEW VAULT",
            font=ctk.CTkFont(family="Courier New", size=14),
            text_color="#888888"
        )
        self.subtitle_label.pack(pady=(0, 20))
        
        self.info_label = ctk.CTkLabel(
            self.main_frame, text="Choose a strong master password.\nThis will encrypt all your data.",
            font=ctk.CTkFont(family="Courier New", size=11),
            text_color="#aaaaaa"
        )
        self.info_label.pack(pady=(0, 20))
        
        # Password entries with proper spacing
        self.password_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.password_frame.pack(pady=10, padx=30)  # Added padding from edges
        
        self.password_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(
            self.password_frame, width=300, height=40, show="●",
            font=ctk.CTkFont(family="Courier New", size=14),
            placeholder_text="New Master Password", textvariable=self.password_var,
            corner_radius=10, border_width=2, border_color="#9571dd"  # Obsidian purple border
        )
        self.password_entry.pack(pady=10)
        
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ctk.CTkEntry(
            self.password_frame, width=300, height=40, show="●",
            font=ctk.CTkFont(family="Courier New", size=14),
            placeholder_text="Confirm Master Password", textvariable=self.confirm_var,
            corner_radius=10, border_width=2, border_color="#9571dd"  # Obsidian purple border
        )
        self.confirm_entry.pack(pady=10)
        self.confirm_entry.bind('<Return>', self.initialize_vault)
        
        self.create_btn = ctk.CTkButton(
            self.main_frame, text=">> CREATE VAULT <<", width=300, height=40,
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            command=self.initialize_vault, fg_color="#00ff41", hover_color="#00ff41", text_color="#000000"
        )
        self.create_btn.pack(pady=20)
        
        self.password_entry.focus()
    
    def initialize_vault(self, event=None):
        password = self.password_var.get()
        confirm = self.confirm_var.get()
        
        if not password or len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters!")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        if self.vault_manager.initialize_vault(password):
            messagebox.showinfo("Success", "🎉 Welcome to Obscura, Hammad!\n\nYour vault has been created successfully.\nYour data is now encrypted with AES-256.")
            self.authenticated = True
            self.master.quit()
        else:
            messagebox.showerror("Error", "Failed to create vault!")
    
    def authenticate(self, event=None):
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your master password!")
            return
        
        if self.vault_manager.unlock_vault(password):
            self.authenticated = True
            self.master.quit()
        else:
            messagebox.showerror("Error", "🚨 INVALID MASTER PASSWORD!")
            self.password_var.set("")

class AddEntryDialog(ctk.CTkToplevel):
    def __init__(self, parent, entry_type='api_key', entry_data=None):
        super().__init__(parent)
        
        self.entry_type = entry_type
        self.entry_data = entry_data
        self.result = None
        
        type_names = {
            'api_key': 'API Key',
            'password': 'Password',
            'credit_card': 'Credit Card',
            'debit_card': 'Debit Card',
            'bank_details': 'Bank Details',
            'secure_note': 'Secure Note'
        }
        
        type_name = type_names.get(entry_type, 'Entry')
        action = "Edit" if entry_data else "Add"
        
        self.title(f"🔐 {action} {type_name}")
        self.geometry("600x650")
        self.configure(fg_color="#000011")
        self.resizable(False, False)
        
        self.transient(parent)
        self.grab_set()
        
        self.center_window()
        self.setup_ui()
    
    def center_window(self):
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.winfo_screenheight() // 2) - (650 // 2)
        self.geometry(f"600x650+{x}+{y}")
    
    def setup_ui(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="#0a0a0a", corner_radius=15)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        type_icons = {'api_key': '🔑', 'password': '🔒', 'credit_card': '💳', 'secure_note': '📝'}
        icon = type_icons.get(self.entry_type, '📄')
        type_name = self.entry_type.replace('_', ' ').title()
        action = "Edit" if self.entry_data else "Add"
        
        self.title_label = ctk.CTkLabel(
            self.main_frame, text=f"{icon} {action} {type_name}",
            font=ctk.CTkFont(size=20, weight="bold"), text_color="#00ff41"
        )
        self.title_label.pack(pady=20)
        
        # Security notice
        self.security_label = ctk.CTkLabel(
            self.main_frame, text="🛡️ All data will be encrypted with AES-256-GCM",
            font=ctk.CTkFont(size=11), text_color="#888888"
        )
        self.security_label.pack(pady=(0, 20))
        
        # Scrollable form
        self.scroll_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color="transparent")
        self.scroll_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.create_form()
        self.create_buttons()
        
        if hasattr(self, 'name_entry'):
            self.name_entry.focus()
    
    def create_form(self):
        # Name field
        self.add_label("🏷️ Name:")
        self.name_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text=f"Enter {self.entry_type.replace('_', ' ')} name"
        )
        self.name_entry.pack(pady=(5, 15))
        
        # Category field
        self.add_label("📁 Category:")
        categories = ["OpenAI", "Google", "GitHub", "Stripe", "AWS", "Banking", "SBI Bank", "HDFC Bank", "ICICI Bank", "Axis Bank", "Social", "Work", "Personal", "Other"]
        self.category_combo = ctk.CTkComboBox(
            self.scroll_frame, width=500, height=35, values=categories
        )
        self.category_combo.pack(pady=(5, 15))
        
        # Description field
        self.add_label("📝 Description (optional):")
        self.desc_text = ctk.CTkTextbox(self.scroll_frame, width=500, height=60)
        self.desc_text.pack(pady=(5, 20))
        
        # Type-specific fields
        if self.entry_type == 'api_key':
            self.create_api_key_fields()
        elif self.entry_type == 'password':
            self.create_password_fields()
        elif self.entry_type == 'credit_card':
            self.create_credit_card_fields()
        elif self.entry_type == 'debit_card':
            self.create_debit_card_fields()
        elif self.entry_type == 'bank_details':
            self.create_bank_details_fields()
        elif self.entry_type == 'secure_note':
            self.create_secure_note_fields()
        
        # Fill existing data if editing
        if self.entry_data:
            self.fill_existing_data()
    
    def add_label(self, text):
        label = ctk.CTkLabel(
            self.scroll_frame, text=text, font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#aaaaaa", anchor="w"
        )
        label.pack(anchor="w", pady=(10, 0))
    
    def create_api_key_fields(self):
        self.add_label("🔑 API Key:")
        self.key_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Enter your API key", show="●"
        )
        self.key_entry.pack(pady=(5, 10))
        
        self.show_key_btn = ctk.CTkButton(
            self.scroll_frame, text="👁️ Show Key", width=100, height=25,
            command=self.toggle_key_visibility, fg_color="#2d2d2d"
        )
        self.show_key_btn.pack(pady=(0, 15))
    
    def create_password_fields(self):
        self.add_label("🌐 Website/Service:")
        self.website_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="e.g., https://example.com"
        )
        self.website_entry.pack(pady=(5, 15))
        
        self.add_label("👤 Username:")
        self.username_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Username or login"
        )
        self.username_entry.pack(pady=(5, 15))
        
        self.add_label("🔒 Password:")
        self.password_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Enter password", show="●"
        )
        self.password_entry.pack(pady=(5, 10))
        
        # Password controls
        btn_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        btn_frame.pack(pady=(0, 15))
        
        self.show_pass_btn = ctk.CTkButton(
            btn_frame, text="👁️ Show", width=80, height=25,
            command=self.toggle_password_visibility, fg_color="#2d2d2d"
        )
        self.show_pass_btn.pack(side="left", padx=(0, 10))
        
        self.generate_btn = ctk.CTkButton(
            btn_frame, text="🎲 Generate", width=100, height=25,
            command=self.generate_password, fg_color="#9c27b0"
        )
        self.generate_btn.pack(side="left")
    
    def create_credit_card_fields(self):
        self.add_label("🏪 Card Name:")
        self.card_name_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="e.g., Personal Visa"
        )
        self.card_name_entry.pack(pady=(5, 15))
        
        self.add_label("💳 Card Number:")
        self.card_number_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="1234 5678 9012 3456", show="●"
        )
        self.card_number_entry.pack(pady=(5, 15))
        
        self.add_label("🔢 CVV:")
        self.cvv_entry = ctk.CTkEntry(
            self.scroll_frame, width=100, height=35,
            placeholder_text="123", show="●"
        )
        self.cvv_entry.pack(pady=(5, 15))
    
    def create_debit_card_fields(self):
        self.add_label("🏦 Bank Name:")
        self.bank_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="e.g., State Bank of India, HDFC Bank"
        )
        self.bank_entry.pack(pady=(5, 15))
        
        self.add_label("💰 Card Number:")
        self.card_number_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="1234 5678 9012 3456", show="●"
        )
        self.card_number_entry.pack(pady=(5, 10))
        
        self.show_card_btn = ctk.CTkButton(
            self.scroll_frame, text="👁️ Show Number", width=120, height=25,
            command=self.toggle_card_visibility, fg_color="#2d2d2d"
        )
        self.show_card_btn.pack(pady=(0, 15))
        
        # Expiry and PIN
        exp_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        exp_frame.pack(fill="x", pady=(0, 15))
        
        exp_label = ctk.CTkLabel(exp_frame, text="📅 Expiry:", font=ctk.CTkFont(size=12, weight="bold"))
        exp_label.pack(side="left")
        
        self.exp_month_combo = ctk.CTkComboBox(
            exp_frame, width=80, height=35,
            values=[f"{i:02d}" for i in range(1, 13)]
        )
        self.exp_month_combo.pack(side="left", padx=(10, 5))
        
        slash_label = ctk.CTkLabel(exp_frame, text="/", font=ctk.CTkFont(size=16))
        slash_label.pack(side="left", padx=5)
        
        current_year = datetime.now().year
        self.exp_year_combo = ctk.CTkComboBox(
            exp_frame, width=80, height=35,
            values=[str(i) for i in range(current_year, current_year + 15)]
        )
        self.exp_year_combo.pack(side="left", padx=(5, 20))
        
        pin_label = ctk.CTkLabel(exp_frame, text="🔢 PIN:", font=ctk.CTkFont(size=12, weight="bold"))
        pin_label.pack(side="left", padx=(20, 10))
        
        self.pin_entry = ctk.CTkEntry(
            exp_frame, width=80, height=35,
            placeholder_text="1234", show="●"
        )
        self.pin_entry.pack(side="left")
        
        self.add_label("🏪 Card Holder Name:")
        self.holder_name_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Name as on card"
        )
        self.holder_name_entry.pack(pady=(5, 15))
    
    def create_bank_details_fields(self):
        self.add_label("🏦 Bank Name:")
        self.bank_name_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="e.g., State Bank of India"
        )
        self.bank_name_entry.pack(pady=(5, 15))
        
        self.add_label("🔢 Account Number:")
        self.account_number_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Account Number", show="●"
        )
        self.account_number_entry.pack(pady=(5, 15))
        
        self.add_label("🏧 IFSC Code:")
        self.ifsc_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="e.g., SBIN0001234"
        )
        self.ifsc_entry.pack(pady=(5, 15))
        
        self.add_label("👤 Username/Customer ID:")
        self.username_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Net Banking Username or Customer ID"
        )
        self.username_entry.pack(pady=(5, 15))
        
        self.add_label("🔒 Login Password:")
        self.login_password_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Net Banking Login Password", show="●"
        )
        self.login_password_entry.pack(pady=(5, 10))
        
        # Password controls
        btn_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        btn_frame.pack(pady=(0, 15))
        
        self.show_login_btn = ctk.CTkButton(
            btn_frame, text="👁️ Show", width=80, height=25,
            command=self.toggle_login_visibility, fg_color="#2d2d2d"
        )
        self.show_login_btn.pack(side="left", padx=(0, 10))
        
        # Indian banking specific fields
        self.add_label("📱 Transaction Password/MPIN:")
        self.transaction_password_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Transaction Password or MPIN", show="●"
        )
        self.transaction_password_entry.pack(pady=(5, 15))
        
        self.add_label("🔐 Profile Password (if any):")
        self.profile_password_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="SBI Profile Password, HDFC Profile Password, etc.", show="●"
        )
        self.profile_password_entry.pack(pady=(5, 15))
        
        self.add_label("🆔 UPI PIN:")
        self.upi_pin_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="4 or 6 digit UPI PIN", show="●"
        )
        self.upi_pin_entry.pack(pady=(5, 15))
        
        self.add_label("📞 Registered Mobile:")
        self.mobile_entry = ctk.CTkEntry(
            self.scroll_frame, width=500, height=35,
            placeholder_text="Mobile number linked to account"
        )
        self.mobile_entry.pack(pady=(5, 15))
    
    def toggle_key_visibility(self):
        if self.key_entry.cget("show") == "●":
            self.key_entry.configure(show="")
            self.show_key_btn.configure(text="🙈 Hide Key")
        else:
            self.key_entry.configure(show="●")
            self.show_key_btn.configure(text="👁️ Show Key")
    
    def toggle_password_visibility(self):
        if self.password_entry.cget("show") == "●":
            self.password_entry.configure(show="")
            self.show_pass_btn.configure(text="🙈 Hide")
        else:
            self.password_entry.configure(show="●")
            self.show_pass_btn.configure(text="👁️ Show")
    
    def generate_password(self):
        # Generate strong password
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(chars) for _ in range(16))
        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
    def generate_password(self):
        # Generate strong password
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(chars) for _ in range(16))
        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
        # Show generated password briefly
        self.password_entry.configure(show="")
        self.show_pass_btn.configure(text="🙈 Hide")
        
        messagebox.showinfo("Password Generated", "🎲 Strong password generated!")
    
    def fill_existing_data(self):
        # Fill common fields
        self.name_entry.insert(0, self.entry_data.get('name', ''))
        self.category_combo.set(self.entry_data.get('category', 'Other'))
        self.desc_text.insert("1.0", self.entry_data.get('description', ''))
        
        # Fill type-specific fields
        data = self.entry_data.get('data', {})
        
        if self.entry_type == 'api_key':
            key = data.get('key', '')
            self.key_entry.insert(0, key)
        
        elif self.entry_type == 'password':
            self.website_entry.insert(0, data.get('website', ''))
            self.username_entry.insert(0, data.get('username', ''))
            self.password_entry.insert(0, data.get('password', ''))
        
        elif self.entry_type == 'credit_card':
            self.card_name_entry.insert(0, data.get('name', ''))
            self.card_number_entry.insert(0, data.get('number', ''))
            self.cvv_entry.insert(0, data.get('cvv', ''))
        
        elif self.entry_type == 'debit_card':
            self.bank_entry.insert(0, data.get('bank', ''))
            self.card_number_entry.insert(0, data.get('number', ''))
            if data.get('exp_month'):
                self.exp_month_combo.set(data['exp_month'])
            if data.get('exp_year'):
                self.exp_year_combo.set(data['exp_year'])
            self.pin_entry.insert(0, data.get('pin', ''))
            self.holder_name_entry.insert(0, data.get('holder_name', ''))
        
        elif self.entry_type == 'bank_details':
            self.bank_name_entry.insert(0, data.get('bank_name', ''))
            self.account_number_entry.insert(0, data.get('account_number', ''))
            self.ifsc_entry.insert(0, data.get('ifsc_code', ''))
            self.username_entry.insert(0, data.get('username', ''))
            self.login_password_entry.insert(0, data.get('login_password', ''))
            self.transaction_password_entry.insert(0, data.get('transaction_password', ''))
            self.profile_password_entry.insert(0, data.get('profile_password', ''))
            self.upi_pin_entry.insert(0, data.get('upi_pin', ''))
            self.mobile_entry.insert(0, data.get('mobile', ''))
        
        elif self.entry_type == 'secure_note':
            self.content_text.insert("1.0", data.get('content', ''))
    
    def create_buttons(self):
        self.button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.button_frame.pack(pady=20)
        
        # Cancel button
        self.cancel_btn = ctk.CTkButton(
            self.button_frame, text="Cancel", width=100, height=35,
            command=self.destroy, fg_color="#666666", hover_color="#555555"
        )
        self.cancel_btn.pack(side="left", padx=10)
        
        # Save button
        action = "Update" if self.entry_data else "Add"
        self.save_btn = ctk.CTkButton(
            self.button_frame, text=f"🔐 {action} & Encrypt", width=150, height=35,
            command=self.save, fg_color="#00ff41", hover_color="#00cc33", text_color="#000000"
        )
        self.save_btn.pack(side="left", padx=10)
    
    def save(self):
        # Validate common fields
        name = self.name_entry.get().strip()
        category = self.category_combo.get()
        description = self.desc_text.get("1.0", tk.END).strip()
        
        if not name:
            messagebox.showerror("Error", "Name is required!")
            return
        
        # Validate and collect type-specific data
        if self.entry_type == 'api_key':
            key = self.key_entry.get().strip()
            if not key:
                messagebox.showerror("Error", "API key is required!")
                return
            data = {'key': key}
        
        elif self.entry_type == 'password':
            website = self.website_entry.get().strip()
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            
            if not password:
                messagebox.showerror("Error", "Password is required!")
                return
            
            data = {
                'website': website,
                'username': username,
                'password': password
            }
        
        elif self.entry_type == 'debit_card':
            bank = self.bank_entry.get().strip()
            number = self.card_number_entry.get().strip().replace(' ', '')
            exp_month = self.exp_month_combo.get()
            exp_year = self.exp_year_combo.get()
            pin = self.pin_entry.get().strip()
            holder_name = self.holder_name_entry.get().strip()
            
            if not number:
                messagebox.showerror("Error", "Card number is required!")
                return
            if not pin:
                messagebox.showerror("Error", "PIN is required!")
                return
            
            data = {
                'bank': bank,
                'number': number,
                'exp_month': exp_month,
                'exp_year': exp_year,
                'pin': pin,
                'holder_name': holder_name
            }
        
        elif self.entry_type == 'bank_details':
            bank_name = self.bank_name_entry.get().strip()
            account_number = self.account_number_entry.get().strip()
            ifsc = self.ifsc_entry.get().strip()
            username = self.username_entry.get().strip()
            login_password = self.login_password_entry.get().strip()
            transaction_password = self.transaction_password_entry.get().strip()
            profile_password = self.profile_password_entry.get().strip()
            upi_pin = self.upi_pin_entry.get().strip()
            mobile = self.mobile_entry.get().strip()
            
            if not bank_name:
                messagebox.showerror("Error", "Bank name is required!")
                return
            if not account_number:
                messagebox.showerror("Error", "Account number is required!")
                return
            
            data = {
                'bank_name': bank_name,
                'account_number': account_number,
                'ifsc_code': ifsc,
                'username': username,
                'login_password': login_password,
                'transaction_password': transaction_password,
                'profile_password': profile_password,
                'upi_pin': upi_pin,
                'mobile': mobile
            }
        
        elif self.entry_type == 'secure_note':
            content = self.content_text.get("1.0", tk.END).strip()
            if not content:
                messagebox.showerror("Error", "Note content is required!")
                return
            
            data = {'content': content}
        
        else:
            messagebox.showerror("Error", "Unknown entry type!")
            return
        
        # Create result
        self.result = {
            'name': name,
            'type': self.entry_type,
            'data': data,
            'category': category,
            'description': description
        }
        
        self.destroy()

class ObscuraVault:
    def __init__(self, master, vault_manager):
        self.master = master
        self.vault_manager = vault_manager
        
        self.master.title("OBSCURA - Secure Vault")
        self.master.geometry("1400x800")  # Made wider for more buttons
        self.master.configure(bg='#000011')
        
        self.setup_ui()
        self.refresh_entries()
        
        # Auto-lock timer (30 minutes)
        self.reset_auto_lock()
        self.master.bind('<Button-1>', lambda e: self.reset_auto_lock())
        self.master.bind('<Key>', lambda e: self.reset_auto_lock())
    
    def reset_auto_lock(self):
        if hasattr(self, 'auto_lock_timer'):
            self.master.after_cancel(self.auto_lock_timer)
        self.auto_lock_timer = self.master.after(1800000, self.auto_lock)  # 30 minutes
    
    def auto_lock(self):
        if messagebox.askyesno("Auto-Lock", "Vault has been idle for 30 minutes.\nLock vault for security?"):
            self.lock_vault()
    
    def lock_vault(self):
        self.vault_manager.lock_vault()
        self.master.quit()
    
    def setup_ui(self):
        # Header
        self.header_frame = ctk.CTkFrame(self.master, height=80, fg_color="#0a0a0a")
        self.header_frame.pack(fill="x", padx=10, pady=(10, 0))
        self.header_frame.pack_propagate(False)
        
        # Left side - Title
        self.title_left = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.title_left.pack(side="left", fill="y", padx=20, pady=20)
        
        self.title_label = ctk.CTkLabel(
            self.title_left, text="🔐 OBSCURA VAULT - ENCRYPTED",
            font=ctk.CTkFont(size=24, weight="bold"), text_color="#9571dd"  # Obsidian purple
        )
        self.title_label.pack(anchor="w")
        
        self.owner_label = ctk.CTkLabel(
            self.title_left, text="Hammad Malik's Secure Vault",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#c5aff3"  # Light purple
        )
        self.owner_label.pack(anchor="w")
        
        # Right side - Controls
        self.header_right = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.header_right.pack(side="right", fill="y", padx=20, pady=20)
        
        # Lock button
        self.lock_btn = ctk.CTkButton(
            self.header_right, text="🔒 LOCK VAULT", width=120, height=35,
            command=self.lock_vault, fg_color="#ff4444", hover_color="#cc3333"
        )
        self.lock_btn.pack(side="right", padx=(10, 0))
        
        # Status
        self.status_label = ctk.CTkLabel(
            self.header_right, text="🛡️ AES-256 ENCRYPTED • SECURE",
            font=ctk.CTkFont(size=12), text_color="#888888"
        )
        self.status_label.pack(side="right", padx=(0, 10))
        
        # Toolbar
        self.toolbar_frame = ctk.CTkFrame(self.master, height=60, fg_color="#0a0a0a")
        self.toolbar_frame.pack(fill="x", padx=10, pady=5)
        self.toolbar_frame.pack_propagate(False)
        
        # Search
        self.search_frame = ctk.CTkFrame(self.toolbar_frame, fg_color="transparent")
        self.search_frame.pack(side="left", fill="x", expand=True, padx=20, pady=10)
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.on_search)
        
        self.search_entry = ctk.CTkEntry(
            self.search_frame, width=250, height=35,
            placeholder_text="🔍 Search encrypted entries...",
            textvariable=self.search_var, font=ctk.CTkFont(size=12)
        )
        self.search_entry.pack(side="left", padx=(0, 10))
        
        # Type filter
        self.type_filter = ctk.CTkComboBox(
            self.search_frame, width=120, height=35,
            values=["All Types", "API Keys", "Passwords", "Credit Cards", "Debit Cards", "Bank Details", "Secure Notes"],
            command=self.on_filter_change
        )
        self.type_filter.set("All Types")
        self.type_filter.pack(side="left", padx=(0, 10))
        
        # Category filter
        self.category_filter = ctk.CTkComboBox(
            self.search_frame, width=120, height=35,
            values=["All Categories", "OpenAI", "Google", "GitHub", "Stripe", "AWS", "Banking", "SBI Bank", "HDFC Bank", "ICICI Bank", "Axis Bank", "Social", "Work", "Personal", "Other"],
            command=self.on_filter_change
        )
        self.category_filter.set("All Categories")
        self.category_filter.pack(side="left", padx=(0, 10))
        
        # Add buttons with text labels
        self.add_frame = ctk.CTkFrame(self.toolbar_frame, fg_color="transparent")
        self.add_frame.pack(side="right", padx=20, pady=10)
        
        self.add_api_btn = ctk.CTkButton(
            self.add_frame, text="🔑 API Key", width=100, height=35,
            command=lambda: self.add_entry('api_key'), fg_color="#00ff41",
            hover_color="#00cc33", text_color="#000000", font=ctk.CTkFont(size=10, weight="bold")
        )
        self.add_api_btn.pack(side="left", padx=2)
        
        self.add_pass_btn = ctk.CTkButton(
            self.add_frame, text="🔒 Password", width=100, height=35,
            command=lambda: self.add_entry('password'), fg_color="#2196f3",
            hover_color="#1976d2", font=ctk.CTkFont(size=10, weight="bold")
        )
        self.add_pass_btn.pack(side="left", padx=2)
        
        self.add_credit_btn = ctk.CTkButton(
            self.add_frame, text="💳 Credit Card", width=110, height=35,
            command=lambda: self.add_entry('credit_card'), fg_color="#ff9800",
            hover_color="#f57c00", font=ctk.CTkFont(size=10, weight="bold")
        )
        self.add_credit_btn.pack(side="left", padx=2)
        
        self.add_debit_btn = ctk.CTkButton(
            self.add_frame, text="💰 Debit Card", width=110, height=35,
            command=lambda: self.add_entry('debit_card'), fg_color="#4caf50",
            hover_color="#388e3c", font=ctk.CTkFont(size=10, weight="bold")
        )
        self.add_debit_btn.pack(side="left", padx=2)
        
        self.add_bank_btn = ctk.CTkButton(
            self.add_frame, text="🏦 Banking", width=100, height=35,
            command=lambda: self.add_entry('bank_details'), fg_color="#607d8b",
            hover_color="#455a64", font=ctk.CTkFont(size=10, weight="bold")
        )
        self.add_bank_btn.pack(side="left", padx=2)
        
        self.add_note_btn = ctk.CTkButton(
            self.add_frame, text="📝 Note", width=90, height=35,
            command=lambda: self.add_entry('secure_note'), fg_color="#9c27b0",
            hover_color="#7b1fa2", font=ctk.CTkFont(size=10, weight="bold")
        )
        self.add_note_btn.pack(side="left", padx=2)
        
        # Main content
        self.content_frame = ctk.CTkFrame(self.master, fg_color="#0a0a0a")
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        
        self.scrollable_frame = ctk.CTkScrollableFrame(
            self.content_frame, fg_color="transparent"
        )
        self.scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Stats
        self.stats_frame = ctk.CTkFrame(self.master, height=50, fg_color="#0a0a0a")
        self.stats_frame.pack(fill="x", padx=10, pady=(0, 10))
        self.stats_frame.pack_propagate(False)
        
        self.stats_label = ctk.CTkLabel(
            self.stats_frame, text="", font=ctk.CTkFont(size=11), text_color="#888888"
        )
        self.stats_label.pack(pady=15)
    
    def on_search(self, *args):
        self.refresh_entries()
    
    def on_filter_change(self, value=None):
        self.refresh_entries()
    
    def refresh_entries(self):
        # Clear existing
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        # Get all entries
        all_entries = self.vault_manager.list_entries()
        search_term = self.search_var.get().lower()
        type_filter = self.type_filter.get()
        category_filter = self.category_filter.get()
        
        filtered_entries = []
        for entry in all_entries:
            # Search filter
            if search_term and search_term not in entry.get('name', '').lower():
                continue
            
            # Type filter
            if type_filter != "All Types":
                entry_type = entry.get('type', 'api_key')
                type_map = {
                    "API Keys": "api_key",
                    "Passwords": "password",
                    "Credit Cards": "credit_card",
                    "Debit Cards": "debit_card",
                    "Bank Details": "bank_details",
                    "Secure Notes": "secure_note"
                }
                if entry_type != type_map.get(type_filter, ''):
                    continue
            
            # Category filter
            if category_filter != "All Categories" and entry.get('category', 'Other') != category_filter:
                continue
            
            filtered_entries.append(entry)
        
        if not filtered_entries:
            no_entries_label = ctk.CTkLabel(
                self.scrollable_frame, text="🔍 No encrypted entries found\n\nTry adjusting your search or add a new entry",
                font=ctk.CTkFont(size=16), text_color="#666666"
            )
            no_entries_label.pack(pady=50)
        else:
            for entry_data in filtered_entries:
                self.create_entry_card(entry_data)
        
        # Update stats
        self.update_stats(len(all_entries))
    
    def create_entry_card(self, entry_data):
        card = ctk.CTkFrame(
            self.scrollable_frame, fg_color="#1a1a1a",
            border_width=1, border_color="#333333", corner_radius=10
        )
        card.pack(fill="x", padx=5, pady=5)
        card.grid_columnconfigure(1, weight=1)
        
        # Entry type and category
        entry_type = entry_data.get('type', 'api_key')
        type_icons = {
            'api_key': '🔑', 
            'password': '🔒', 
            'credit_card': '💳', 
            'debit_card': '💰',
            'bank_details': '🏦',
            'secure_note': '📝'
        }
        
        category_colors = {
            "OpenAI": "#10a37f", "Google": "#4285f4", "GitHub": "#24292e",
            "Stripe": "#635bff", "AWS": "#ff9900", "Banking": "#2e7d32",
            "SBI Bank": "#1976d2", "HDFC Bank": "#e53935", "ICICI Bank": "#ff5722", 
            "Axis Bank": "#9c27b0", "Social": "#1976d2", "Work": "#7b1fa2", 
            "Personal": "#d32f2f", "Other": "#6b7280"
        }
        
        type_icon = type_icons.get(entry_type, '📄')
        category_color = category_colors.get(entry_data.get('category', 'Other'), "#6b7280")
        
        type_label = ctk.CTkLabel(
            card, text=f"{type_icon} {entry_data.get('category', 'Other')}",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=category_color, width=100
        )
        type_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        # Name
        name_label = ctk.CTkLabel(
            card, text=entry_data.get('name', 'Unnamed Entry'),
            font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffffff"
        )
        name_label.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        # Last used
        last_used_label = ctk.CTkLabel(
            card, text=f"Last used: {entry_data.get('last_used', 'Never')}",
            font=ctk.CTkFont(size=9), text_color="#888888"
        )
        last_used_label.grid(row=0, column=2, padx=10, pady=5, sticky="e")
        
        # Data display
        data_frame = ctk.CTkFrame(card, fg_color="transparent")
        data_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 10), sticky="ew")
        data_frame.grid_columnconfigure(0, weight=1)
        
        # Display based on entry type
        data = entry_data.get('data', {})
        if entry_type == 'api_key':
            key = data.get('key', '')
            masked_key = self.mask_data(key)
            display_text = f"🔐 API Key: {masked_key}"
        elif entry_type == 'password':
            username = data.get('username', '')
            website = data.get('website', '')
            display_text = f"🔐 {username}@{website}" if username and website else "🔐 Password Entry"
        elif entry_type == 'credit_card':
            number = data.get('number', '')
            masked_number = f"****-****-****-{number[-4:]}" if len(number) >= 4 else "****-****-****-****"
            display_text = f"🔐 Credit Card: {masked_number}"
        elif entry_type == 'debit_card':
            number = data.get('number', '')
            masked_number = f"****-****-****-{number[-4:]}" if len(number) >= 4 else "****-****-****-****"
            bank = data.get('bank', 'Bank')
            display_text = f"🔐 {bank} Debit: {masked_number}"
        elif entry_type == 'bank_details':
            bank_name = data.get('bank_name', 'Bank')
            account = data.get('account_number', '')
            masked_account = f"****{account[-4:]}" if len(account) >= 4 else "****"
            display_text = f"🔐 {bank_name}: {masked_account}"
        else:
            display_text = f"🔐 Secure Note"
        
        data_display = ctk.CTkEntry(
            data_frame, font=ctk.CTkFont(family="Courier", size=11),
            state="readonly", fg_color="#1a1a1a", border_color="#333333"
        )
        data_display.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        data_display.insert(0, display_text)
        
        # Buttons
        buttons_frame = ctk.CTkFrame(data_frame, fg_color="transparent")
        buttons_frame.grid(row=0, column=1, sticky="e")
        
        # Copy button
        copy_btn = ctk.CTkButton(
            buttons_frame, text="📋", width=30, height=30,
            command=lambda: self.copy_entry_data(entry_data),
            fg_color="#00ff41", hover_color="#00cc33", text_color="#000000"
        )
        copy_btn.grid(row=0, column=0, padx=2)
        
        # Edit button
        edit_btn = ctk.CTkButton(
            buttons_frame, text="✏️", width=30, height=30,
            command=lambda: self.edit_entry(entry_data),
            fg_color="#0080ff", hover_color="#0066cc"
        )
        edit_btn.grid(row=0, column=1, padx=2)
        
        # Delete button
        delete_btn = ctk.CTkButton(
            buttons_frame, text="🗑️", width=30, height=30,
            command=lambda: self.delete_entry(entry_data),
            fg_color="#ff4444", hover_color="#cc3333"
        )
        delete_btn.grid(row=0, column=2, padx=2)
        
        # Description
        if entry_data.get('description'):
            desc_label = ctk.CTkLabel(
                card, text=f"🔒 {entry_data['description']}",
                font=ctk.CTkFont(size=10), text_color="#aaaaaa", wraplength=400
            )
            desc_label.grid(row=2, column=0, columnspan=3, padx=10, pady=(0, 10), sticky="w")
    
    def mask_data(self, data):
        if len(data) <= 8:
            return "●" * len(data)
        return data[:4] + "●" * (len(data) - 8) + data[-4:]
    
    def copy_entry_data(self, entry_data):
        try:
            entry_type = entry_data.get('type', 'api_key')
            entry_id = entry_data['id']
            
            if entry_type == 'api_key':
                data = self.vault_manager.get_entry_data(entry_id, 'key')
            elif entry_type == 'password':
                data = self.vault_manager.get_entry_data(entry_id, 'password')
            elif entry_type == 'credit_card':
                data = self.vault_manager.get_entry_data(entry_id, 'number')
            elif entry_type == 'debit_card':
                data = self.vault_manager.get_entry_data(entry_id, 'pin')  # Copy PIN for debit cards
            elif entry_type == 'bank_details':
                data = self.vault_manager.get_entry_data(entry_id, 'login_password')  # Copy main login password
            else:
                data = self.vault_manager.get_entry_data(entry_id, 'content')
            
            if data:
                pyperclip.copy(data)
                messagebox.showinfo("Copied!", f"🔐 {entry_type.replace('_', ' ').title()} copied to clipboard!\n\nClipboard will auto-clear in 30 seconds.")
                
                # Auto-clear clipboard
                def clear_clipboard():
                    time.sleep(30)
                    pyperclip.copy("")
                
                threading.Thread(target=clear_clipboard, daemon=True).start()
                self.refresh_entries()
            else:
                messagebox.showerror("Error", "Failed to decrypt entry data!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy data: {str(e)}")
    
    def add_entry(self, entry_type):
        dialog = AddEntryDialog(self.master, entry_type=entry_type)
        self.master.wait_window(dialog)
        
        if dialog.result:
            if self.vault_manager.add_entry(
                dialog.result['name'],
                dialog.result['type'],
                dialog.result['data'],
                dialog.result['category'],
                dialog.result['description']
            ):
                messagebox.showinfo("Success", f"🔐 {entry_type.replace('_', ' ').title()} '{dialog.result['name']}' encrypted and stored!")
                self.refresh_entries()
            else:
                messagebox.showerror("Error", "Failed to add entry. Name might already exist.")
    
    def edit_entry(self, entry_data):
        dialog = AddEntryDialog(self.master, entry_data=entry_data)
        self.master.wait_window(dialog)
        
        if dialog.result:
            if self.vault_manager.update_entry(
                entry_data['id'],
                dialog.result['name'],
                dialog.result['type'],
                dialog.result['data'],
                dialog.result['category'],
                dialog.result['description']
            ):
                messagebox.showinfo("Success", f"🔐 Entry '{dialog.result['name']}' updated and re-encrypted!")
                self.refresh_entries()
            else:
                messagebox.showerror("Error", "Failed to update entry.")
    
    def delete_entry(self, entry_data):
        entry_type = entry_data.get('type', 'entry').replace('_', ' ').title()
        if messagebox.askyesno("Confirm Delete", 
                             f"🗑️ Are you sure you want to permanently delete this {entry_type}?\n\n" +
                             f"'{entry_data.get('name', 'this entry')}'\n\n" +
                             "This will securely wipe the encrypted data and cannot be undone."):
            if self.vault_manager.delete_entry(entry_data['id']):
                messagebox.showinfo("Deleted", f"🔥 {entry_type} '{entry_data['name']}' securely deleted!")
                self.refresh_entries()
            else:
                messagebox.showerror("Error", "Failed to delete entry.")
    
    def update_stats(self, total_entries):
        all_entries = self.vault_manager.list_entries()
        types = {}
        for entry in all_entries:
            entry_type = entry.get('type', 'api_key')
            # Convert to readable names
            type_names = {
                'api_key': 'API Keys',
                'password': 'Passwords',
                'credit_card': 'Credit Cards', 
                'debit_card': 'Debit Cards',
                'bank_details': 'Bank Details',
                'secure_note': 'Secure Notes'
            }
            readable_type = type_names.get(entry_type, entry_type.replace('_', ' ').title())
            types[readable_type] = types.get(readable_type, 0) + 1
        
        type_text = " • ".join([f"{t}: {c}" for t, c in types.items()])
        self.stats_label.configure(text=f"🔐 Hammad's Encrypted Vault: {total_entries} entries | {type_text} | AES-256")

def main():
    # Initialize vault manager
    vault_manager = ObscuraVaultManager()
    
    # Create authentication window
    auth_root = ctk.CTk()
    auth_app = ObscuraAuth(auth_root, vault_manager)
    auth_root.mainloop()
    
    # Check if authentication was successful
    if not auth_app.authenticated:
        return
    
    # Create main vault window
    main_root = ctk.CTk()
    vault_app = ObscuraVault(main_root, vault_manager)
    main_root.mainloop()
    
    # Lock vault when exiting
    vault_manager.lock_vault()

if __name__ == "__main__":
    main()