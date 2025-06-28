# #!/usr/bin/env python3
# """
# OBSCURA CLI - Secure Terminal Interface
# The hacker's way to manage encrypted data
# """

# import sys
# import os
# import time
# import random
# import argparse
# import getpass
# from datetime import datetime
# import json

# # Add the main obscura module to path
# sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# try:
#     from obscura_final import ObscuraVaultManager, ObscuraCrypto
# except ImportError:
#     print("❌ Error: obscura_final.py not found in the same directory!")
#     print("   Make sure both obscura_cli.py and obscura_final.py are in the same folder.")
#     sys.exit(1)

# # Terminal colors and styling
# class Colors:
#     RESET = '\033[0m'
#     BOLD = '\033[1m'
#     DIM = '\033[2m'
    
#     # Matrix green theme
#     GREEN = '\033[32m'
#     BRIGHT_GREEN = '\033[92m'
#     DARK_GREEN = '\033[2;32m'
    
#     # Status colors
#     RED = '\033[31m'
#     YELLOW = '\033[33m'
#     BLUE = '\033[34m'
#     MAGENTA = '\033[35m'
#     CYAN = '\033[36m'
#     WHITE = '\033[37m'
    
#     # Background colors
#     BG_BLACK = '\033[40m'
#     BG_GREEN = '\033[42m'

# class ObscuraCLI:
#     def __init__(self):
#         self.vault_manager = ObscuraVaultManager()
#         self.authenticated = False
#         self.session_start = None
        
#     def print_banner(self):
#             """Display the epic ASCII banner with Obsidian-style gradient"""
#     # Obsidian-inspired gradient colors
#             purple1 = '\033[38;2;197;175;243m'  # #c5aff3 (light purple)
#             purple2 = '\033[38;2;149;113;221m'  # #9571dd (medium purple) 
#             purple3 = '\033[38;2;76;36;157m'    # #4c249d (dark purple)

#             banner = f"""{purple2}
#           {purple3}██████╗ ██████╗ ███████╗{purple3} ██████╗██╗   ██╗{purple3}██████╗  █████╗ 
#           {purple3}██╔═══██╗██╔══██╗██╔════╝{purple3}██╔════╝██║   ██║{purple3}██╔══██╗██╔══██╗
#           {purple3}██║   ██║██████╔╝███████╗{purple3}██║     ██║   ██║{purple2}██████╔╝███████║
#           {purple3}██║   ██║██╔══██╗╚════██║{purple2}██║     ██║   ██║{purple2}██╔══██╗██╔══██║
#           {purple3}╚██████╔╝██████╔╝{purple2}███████║{purple2}╚██████╗╚██████╔╝{purple2}██║  ██║██║  ██║
#           {purple2}╚═════╝ ╚═════╝ ╚══════╝{purple2} ╚═════╝ ╚═════╝{purple3} ╚═╝  ╚═╝╚═╝  ╚═╝{Colors.RESET}
                                                            
#           {Colors.GREEN}[SECURE TERMINAL ACTIVATED]{Colors.RESET} - {Colors.CYAN}AES-256 ENCRYPTED{Colors.RESET}
#           {Colors.DIM}Type 'help' for commands or 'exit' to terminate session{Colors.RESET}
#         """
#             print(banner)
        
#     def print_matrix_effect(self, duration=2):
#         """Cool matrix-style loading effect"""
#         chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?"
        
#         print(f"{Colors.GREEN}", end="", flush=True)
#         start_time = time.time()
        
#         while time.time() - start_time < duration:
#             for _ in range(50):
#                 print(random.choice(chars), end="", flush=True)
#             print(f"\r{' ' * 50}\r", end="", flush=True)
#             time.sleep(0.1)
        
#         print(f"{Colors.RESET}", end="", flush=True)
    
#     def print_status(self, message, status="info"):
#         """Print colored status messages"""
#         icons = {
#             "success": f"{Colors.BRIGHT_GREEN}✓{Colors.RESET}",
#             "error": f"{Colors.RED}✗{Colors.RESET}",
#             "warning": f"{Colors.YELLOW}⚠{Colors.RESET}",
#             "info": f"{Colors.CYAN}ℹ{Colors.RESET}",
#             "secure": f"{Colors.GREEN}🔐{Colors.RESET}",
#             "loading": f"{Colors.YELLOW}⏳{Colors.RESET}"
#         }
        
#         icon = icons.get(status, icons["info"])
#         print(f"{icon} {message}")
    
#     def print_error(self, message):
#         """Print error message with styling"""
#         print(f"{Colors.RED}╭─ ERROR ─────────────────────────────────────────╮{Colors.RESET}")
#         print(f"{Colors.RED}│{Colors.RESET} {message:<47} {Colors.RED}│{Colors.RESET}")
#         print(f"{Colors.RED}╰─────────────────────────────────────────────────╯{Colors.RESET}")
    
#     def print_success(self, message):
#         """Print success message with styling"""
#         print(f"{Colors.GREEN}╭─ SUCCESS ───────────────────────────────────────╮{Colors.RESET}")
#         print(f"{Colors.GREEN}│{Colors.RESET} {message:<47} {Colors.GREEN}│{Colors.RESET}")
#         print(f"{Colors.GREEN}╰─────────────────────────────────────────────────╯{Colors.RESET}")
    
#     def authenticate(self):
#         """Handle authentication with style"""
#         if not self.vault_manager.is_vault_initialized():
#             self.print_status("No vault found. Initializing new secure vault...", "warning")
#             return self.initialize_vault()
        
#         print(f"\n{Colors.YELLOW}╭─ AUTHENTICATION REQUIRED ──────────────────────╮{Colors.RESET}")
#         print(f"{Colors.YELLOW}│{Colors.RESET} Enter master password to access vault       {Colors.YELLOW}│{Colors.RESET}")
#         print(f"{Colors.YELLOW}╰─────────────────────────────────────────────────╯{Colors.RESET}")
        
#         max_attempts = 3
#         for attempt in range(max_attempts):
#             try:
#                 password = getpass.getpass(f"{Colors.GREEN}[VAULT]{Colors.RESET} Master Password: ")
                
#                 self.print_status("Verifying credentials...", "loading")
#                 self.print_matrix_effect(1)
                
#                 if self.vault_manager.unlock_vault(password):
#                     self.authenticated = True
#                     self.session_start = datetime.now()
#                     self.print_success("Authentication successful!")
#                     self.print_status(f"Session started: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}", "info")
#                     return True
#                 else:
#                     remaining = max_attempts - attempt - 1
#                     if remaining > 0:
#                         self.print_error(f"Invalid password! {remaining} attempts remaining")
#                     else:
#                         self.print_error("Authentication failed! Maximum attempts exceeded")
                        
#             except KeyboardInterrupt:
#                 print(f"\n{Colors.YELLOW}Authentication cancelled{Colors.RESET}")
#                 return False
        
#         return False
    
#     def initialize_vault(self):
#         """Initialize new vault with master password"""
#         print(f"\n{Colors.CYAN}╭─ VAULT INITIALIZATION ──────────────────────────╮{Colors.RESET}")
#         print(f"{Colors.CYAN}│{Colors.RESET} Creating new encrypted vault                {Colors.CYAN}│{Colors.RESET}")
#         print(f"{Colors.CYAN}│{Colors.RESET} Choose a strong master password             {Colors.CYAN}│{Colors.RESET}")
#         print(f"{Colors.CYAN}╰─────────────────────────────────────────────────╯{Colors.RESET}")
        
#         while True:
#             try:
#                 password = getpass.getpass(f"{Colors.GREEN}[NEW]{Colors.RESET} Master Password: ")
#                 if len(password) < 8:
#                     self.print_error("Password must be at least 8 characters!")
#                     continue
                
#                 confirm = getpass.getpass(f"{Colors.GREEN}[CONFIRM]{Colors.RESET} Repeat Password: ")
#                 if password != confirm:
#                     self.print_error("Passwords do not match!")
#                     continue
                
#                 self.print_status("Initializing vault with AES-256 encryption...", "loading")
#                 self.print_matrix_effect(2)
                
#                 if self.vault_manager.initialize_vault(password):
#                     self.authenticated = True
#                     self.session_start = datetime.now()
#                     self.print_success("Vault created successfully!")
#                     self.print_status("Your data is now protected with military-grade encryption", "secure")
#                     return True
#                 else:
#                     self.print_error("Failed to create vault!")
#                     return False
                    
#             except KeyboardInterrupt:
#                 print(f"\n{Colors.YELLOW}Vault initialization cancelled{Colors.RESET}")
#                 return False
    
#     def cmd_help(self, args=None):
#         """Display help information"""
#         help_text = f"""
# {Colors.BRIGHT_GREEN}OBSCURA CLI COMMANDS{Colors.RESET}
# {Colors.DIM}═══════════════════════════════════════════════════════════════════{Colors.RESET}

# {Colors.CYAN}VAULT MANAGEMENT:{Colors.RESET}
#   {Colors.GREEN}list{Colors.RESET} [type]           List all entries or filter by type
#   {Colors.GREEN}get{Colors.RESET} <name>            Retrieve and copy entry to clipboard
#   {Colors.GREEN}add{Colors.RESET} <type>            Add new entry (api_key, password, credit_card, secure_note)
#   {Colors.GREEN}edit{Colors.RESET} <name>           Edit existing entry
#   {Colors.GREEN}delete{Colors.RESET} <name>         Delete entry permanently
#   {Colors.GREEN}search{Colors.RESET} <term>         Search entries by name or description

# {Colors.CYAN}VAULT INFO:{Colors.RESET}
#   {Colors.GREEN}stats{Colors.RESET}                 Show vault statistics
#   {Colors.GREEN}status{Colors.RESET}                Display session status
#   {Colors.GREEN}export{Colors.RESET} <file>         Export encrypted backup

# {Colors.CYAN}SESSION:{Colors.RESET}
#   {Colors.GREEN}lock{Colors.RESET}                  Lock vault and clear session
#   {Colors.GREEN}clear{Colors.RESET}                 Clear terminal screen
#   {Colors.GREEN}help{Colors.RESET}                  Show this help message
#   {Colors.GREEN}exit{Colors.RESET}                  Exit Obscura CLI

# {Colors.CYAN}EXAMPLES:{Colors.RESET}
#   {Colors.DIM}obscura> list api_key              # List only API keys
#   obscura> get "OpenAI GPT-4"           # Get specific entry
#   obscura> add password                 # Add new password entry
#   obscura> search github                # Search for entries containing 'github'{Colors.RESET}

# {Colors.YELLOW}TIP:{Colors.RESET} Use quotes around names with spaces: {Colors.GREEN}get "My API Key"{Colors.RESET}
# """
#         print(help_text)
    
#     def cmd_list(self, args=None):
#         """List vault entries with beautiful formatting"""
#         if not self.authenticated:
#             self.print_error("Please authenticate first")
#             return
        
#         entries = self.vault_manager.list_entries()
        
#         # Filter by type if specified
#         filter_type = args[0] if args else None
#         if filter_type:
#             type_map = {
#                 'api_key': 'api_key', 'api': 'api_key', 'key': 'api_key',
#                 'password': 'password', 'pass': 'password', 'pwd': 'password',
#                 'credit_card': 'credit_card', 'card': 'credit_card', 'cc': 'credit_card',
#                 'secure_note': 'secure_note', 'note': 'secure_note', 'notes': 'secure_note'
#             }
#             actual_type = type_map.get(filter_type.lower())
#             if actual_type:
#                 entries = [e for e in entries if e.get('type') == actual_type]
#             else:
#                 self.print_error(f"Unknown type: {filter_type}")
#                 return
        
#         if not entries:
#             self.print_status("No entries found in vault", "info")
#             return
        
#         # Display header
#         print(f"\n{Colors.BRIGHT_GREEN}╭─ VAULT CONTENTS ────────────────────────────────────────────────────────╮{Colors.RESET}")
#         print(f"{Colors.BRIGHT_GREEN}│{Colors.RESET} {'TYPE':<4} {'NAME':<25} {'INFO':<25} {'LAST USED':<15} {Colors.BRIGHT_GREEN}│{Colors.RESET}")
#         print(f"{Colors.BRIGHT_GREEN}├─────────────────────────────────────────────────────────────────────────┤{Colors.RESET}")
        
#         # Type icons and colors
#         type_info = {
#             'api_key': {'icon': '🔑', 'color': Colors.GREEN},
#             'password': {'icon': '🔒', 'color': Colors.BLUE},
#             'credit_card': {'icon': '💳', 'color': Colors.YELLOW},
#             'secure_note': {'icon': '📝', 'color': Colors.MAGENTA}
#         }
        
#         for entry in entries:
#             entry_type = entry.get('type', 'unknown')
#             info = type_info.get(entry_type, {'icon': '📄', 'color': Colors.WHITE})
            
#             name = entry.get('name', 'Unnamed')[:24]
#             last_used = entry.get('last_used', 'Never')[:14]
            
#             # Generate info based on type
#             data = entry.get('data', {})
#             if entry_type == 'api_key':
#                 key = data.get('key', '')
#                 masked = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else "●" * len(key)
#                 info_text = masked[:24]
#             elif entry_type == 'password':
#                 username = data.get('username', '')
#                 website = data.get('website', '')
#                 info_text = f"{username}@{website}"[:24] if username and website else "Password Entry"
#             elif entry_type == 'credit_card':
#                 number = data.get('number', '')
#                 masked = f"****-****-****-{number[-4:]}" if len(number) >= 4 else "Card"
#                 info_text = masked[:24]
#             else:
#                 info_text = "Secure Note"
            
#             icon = info['icon']
#             color = info['color']
            
#             print(f"{Colors.BRIGHT_GREEN}│{Colors.RESET} {color}{icon}{Colors.RESET}   {name:<25} {Colors.DIM}{info_text:<25}{Colors.RESET} {last_used:<15} {Colors.BRIGHT_GREEN}│{Colors.RESET}")
        
#         print(f"{Colors.BRIGHT_GREEN}╰─────────────────────────────────────────────────────────────────────────╯{Colors.RESET}")
#         print(f"{Colors.DIM}Total entries: {len(entries)} | Filter: {filter_type or 'All'}{Colors.RESET}")
    
#     def cmd_get(self, args):
#         """Retrieve and copy entry to clipboard"""
#         if not self.authenticated:
#             self.print_error("Please authenticate first")
#             return
        
#         if not args:
#             self.print_error("Usage: get <entry_name>")
#             return
        
#         name = ' '.join(args)
#         entries = self.vault_manager.list_entries()
        
#         # Find matching entry
#         matching_entries = [e for e in entries if e.get('name', '').lower() == name.lower()]
        
#         if not matching_entries:
#             # Try partial match
#             matching_entries = [e for e in entries if name.lower() in e.get('name', '').lower()]
            
#             if not matching_entries:
#                 self.print_error(f"Entry '{name}' not found")
#                 return
#             elif len(matching_entries) > 1:
#                 self.print_error(f"Multiple entries match '{name}'. Be more specific:")
#                 for entry in matching_entries:
#                     print(f"  • {entry.get('name')}")
#                 return
        
#         entry = matching_entries[0]
#         entry_type = entry.get('type', 'api_key')
        
#         print(f"{Colors.YELLOW}🔓 Decrypting {entry.get('name')}...{Colors.RESET}")
#         self.print_matrix_effect(1)
        
#         # Get the appropriate field based on type
#         if entry_type == 'api_key':
#             data = self.vault_manager.get_entry_data(entry['id'], 'key')
#             field_name = "API Key"
#         elif entry_type == 'password':
#             data = self.vault_manager.get_entry_data(entry['id'], 'password')
#             field_name = "Password"
#         elif entry_type == 'credit_card':
#             data = self.vault_manager.get_entry_data(entry['id'], 'number')
#             field_name = "Card Number"
#         else:
#             data = self.vault_manager.get_entry_data(entry['id'], 'content')
#             field_name = "Content"
        
#         if data:
#             try:
#                 import pyperclip
#                 pyperclip.copy(data)
#                 self.print_success(f"{field_name} copied to clipboard!")
#                 self.print_status("⏰ Clipboard will auto-clear in 30 seconds", "warning")
                
#                 # Auto-clear clipboard after 30 seconds
#                 import threading
#                 def clear_clipboard():
#                     time.sleep(30)
#                     pyperclip.copy("")
#                     print(f"\n{Colors.DIM}🗑️  Clipboard cleared for security{Colors.RESET}")
                
#                 threading.Thread(target=clear_clipboard, daemon=True).start()
                
#             except ImportError:
#                 self.print_status(f"{field_name}: {data}", "secure")
#                 self.print_status("Install pyperclip for clipboard support: pip install pyperclip", "info")
#         else:
#             self.print_error("Failed to decrypt entry")
    
#     def cmd_add(self, args):
#         """Add new entry with interactive prompts"""
#         if not self.authenticated:
#             self.print_error("Please authenticate first")
#             return
        
#         if not args:
#             self.print_error("Usage: add <type> (api_key, password, credit_card, secure_note)")
#             return
        
#         entry_type = args[0].lower()
#         type_map = {
#             'api_key': 'api_key', 'api': 'api_key', 'key': 'api_key',
#             'password': 'password', 'pass': 'password', 'pwd': 'password',
#             'credit_card': 'credit_card', 'card': 'credit_card', 'cc': 'credit_card',
#             'secure_note': 'secure_note', 'note': 'secure_note', 'notes': 'secure_note'
#         }
        
#         actual_type = type_map.get(entry_type)
#         if not actual_type:
#             self.print_error(f"Unknown type: {entry_type}")
#             self.print_status("Valid types: api_key, password, credit_card, secure_note", "info")
#             return
        
#         print(f"\n{Colors.CYAN}╭─ ADD {actual_type.upper().replace('_', ' ')} ──────────────────────────────────╮{Colors.RESET}")
#         print(f"{Colors.CYAN}│{Colors.RESET} Enter the required information below        {Colors.CYAN}│{Colors.RESET}")
#         print(f"{Colors.CYAN}╰─────────────────────────────────────────────────╯{Colors.RESET}")
        
#         try:
#             # Common fields
#             name = input(f"{Colors.GREEN}Name:{Colors.RESET} ").strip()
#             if not name:
#                 self.print_error("Name is required!")
#                 return
            
#             category = input(f"{Colors.GREEN}Category:{Colors.RESET} [Other] ").strip() or "Other"
#             description = input(f"{Colors.GREEN}Description:{Colors.RESET} [Optional] ").strip()
            
#             # Type-specific fields
#             data = {}
            
#             if actual_type == 'api_key':
#                 key = getpass.getpass(f"{Colors.GREEN}API Key:{Colors.RESET} ")
#                 if not key:
#                     self.print_error("API key is required!")
#                     return
#                 data = {'key': key}
            
#             elif actual_type == 'password':
#                 website = input(f"{Colors.GREEN}Website:{Colors.RESET} ").strip()
#                 username = input(f"{Colors.GREEN}Username:{Colors.RESET} ").strip()
#                 password = getpass.getpass(f"{Colors.GREEN}Password:{Colors.RESET} ")
#                 if not password:
#                     self.print_error("Password is required!")
#                     return
#                 data = {'website': website, 'username': username, 'password': password}
            
#             elif actual_type == 'credit_card':
#                 card_name = input(f"{Colors.GREEN}Card Name:{Colors.RESET} ").strip()
#                 number = input(f"{Colors.GREEN}Card Number:{Colors.RESET} ").strip()
#                 cvv = getpass.getpass(f"{Colors.GREEN}CVV:{Colors.RESET} ")
#                 if not number:
#                     self.print_error("Card number is required!")
#                     return
#                 data = {'name': card_name, 'number': number, 'cvv': cvv}
            
#             elif actual_type == 'secure_note':
#                 print(f"{Colors.GREEN}Content (press Ctrl+D when done):{Colors.RESET}")
#                 content_lines = []
#                 try:
#                     while True:
#                         line = input()
#                         content_lines.append(line)
#                 except EOFError:
#                     pass
#                 content = '\n'.join(content_lines).strip()
#                 if not content:
#                     self.print_error("Content is required!")
#                     return
#                 data = {'content': content}
            
#             # Save entry
#             self.print_status("Encrypting and storing entry...", "loading")
#             self.print_matrix_effect(1)
            
#             if self.vault_manager.add_entry(name, actual_type, data, category, description):
#                 self.print_success(f"{actual_type.replace('_', ' ').title()} '{name}' added successfully!")
#             else:
#                 self.print_error("Failed to add entry. Name might already exist.")
        
#         except KeyboardInterrupt:
#             print(f"\n{Colors.YELLOW}Operation cancelled{Colors.RESET}")
    
#     def cmd_stats(self, args=None):
#         """Display vault statistics"""
#         if not self.authenticated:
#             self.print_error("Please authenticate first")
#             return
        
#         entries = self.vault_manager.list_entries()
        
#         # Calculate statistics
#         total = len(entries)
#         types = {}
#         categories = {}
#         recent_activity = []
        
#         for entry in entries:
#             # Count by type
#             entry_type = entry.get('type', 'unknown')
#             types[entry_type] = types.get(entry_type, 0) + 1
            
#             # Count by category
#             category = entry.get('category', 'Other')
#             categories[category] = categories.get(category, 0) + 1
            
#             # Track recent activity
#             last_used = entry.get('last_used', 'Never')
#             if last_used != 'Never':
#                 recent_activity.append((entry.get('name'), last_used))
        
#         # Display statistics
#         print(f"\n{Colors.BRIGHT_GREEN}╭─ VAULT STATISTICS ──────────────────────────────────────────╮{Colors.RESET}")
#         print(f"{Colors.BRIGHT_GREEN}│{Colors.RESET} {Colors.BOLD}Total Entries:{Colors.RESET} {total:<47} {Colors.BRIGHT_GREEN}│{Colors.RESET}")
#         print(f"{Colors.BRIGHT_GREEN}├─────────────────────────────────────────────────────────────┤{Colors.RESET}")
        
#         # Entry types
#         print(f"{Colors.BRIGHT_GREEN}│{Colors.RESET} {Colors.BOLD}By Type:{Colors.RESET}                                          {Colors.BRIGHT_GREEN}│{Colors.RESET}")
#         type_names = {
#             'api_key': '🔑 API Keys',
#             'password': '🔒 Passwords', 
#             'credit_card': '💳 Credit Cards',
#             'secure_note': '📝 Secure Notes'
#         }
        
#         for entry_type, count in types.items():
#             type_name = type_names.get(entry_type, f'📄 {entry_type}')
#             print(f"{Colors.BRIGHT_GREEN}│{Colors.RESET}   {type_name}: {count:<42} {Colors.BRIGHT_GREEN}│{Colors.RESET}")
        
#         if categories:
#             print(f"{Colors.BRIGHT_GREEN}├─────────────────────────────────────────────────────────────┤{Colors.RESET}")
#             print(f"{Colors.BRIGHT_GREEN}│{Colors.RESET} {Colors.BOLD}Top Categories:{Colors.RESET}                                   {Colors.BRIGHT_GREEN}│{Colors.RESET}")
#             sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]
#             for category, count in sorted_cats:
#                 print(f"{Colors.BRIGHT_GREEN}│{Colors.RESET}   📁 {category}: {count:<42} {Colors.BRIGHT_GREEN}│{Colors.RESET}")
        
#         print(f"{Colors.BRIGHT_GREEN}╰─────────────────────────────────────────────────────────────╯{Colors.RESET}")
        
#         # Session info
#         if self.session_start:
#             session_duration = datetime.now() - self.session_start
#             print(f"{Colors.DIM}Session Duration: {str(session_duration).split('.')[0]} | Encryption: AES-256-GCM{Colors.RESET}")
    
#     def cmd_status(self, args=None):
#         """Display session status"""
#         print(f"\n{Colors.CYAN}╭─ SESSION STATUS ────────────────────────────────────────────╮{Colors.RESET}")
#         print(f"{Colors.CYAN}│{Colors.RESET} Vault Status: {Colors.GREEN}{'UNLOCKED' if self.authenticated else 'LOCKED':<43}{Colors.RESET} {Colors.CYAN}│{Colors.RESET}")
        
#         if self.authenticated:
#             print(f"{Colors.CYAN}│{Colors.RESET} Session Start: {self.session_start.strftime('%Y-%m-%d %H:%M:%S'):<42} {Colors.CYAN}│{Colors.RESET}")
#             duration = datetime.now() - self.session_start
#             print(f"{Colors.CYAN}│{Colors.RESET} Duration: {str(duration).split('.')[0]:<46} {Colors.CYAN}│{Colors.RESET}")
            
#             entries = self.vault_manager.list_entries()
#             print(f"{Colors.CYAN}│{Colors.RESET} Total Entries: {len(entries):<43} {Colors.CYAN}│{Colors.RESET}")
        
#         print(f"{Colors.CYAN}│{Colors.RESET} Encryption: AES-256-GCM                            {Colors.CYAN}│{Colors.RESET}")
#         print(f"{Colors.CYAN}╰─────────────────────────────────────────────────────────────╯{Colors.RESET}")
    
#     def cmd_clear(self, args=None):
#         """Clear terminal screen"""
#         os.system('cls' if os.name == 'nt' else 'clear')
#         self.print_banner()
    
#     def cmd_lock(self, args=None):
#         """Lock vault and clear session"""
#         if self.authenticated:
#             self.vault_manager.lock_vault()
#             self.authenticated = False
#             self.session_start = None
#             self.print_status("Vault locked successfully", "secure")
#         else:
#             self.print_status("Vault is already locked", "info")
    
#     def cmd_search(self, args):
#         """Search entries by name or description"""
#         if not self.authenticated:
#             self.print_error("Please authenticate first")
#             return
        
#         if not args:
#             self.print_error("Usage: search <term>")
#             return
        
#         search_term = ' '.join(args).lower()
#         entries = self.vault_manager.list_entries()
        
#         matches = []
#         for entry in entries:
#             name = entry.get('name', '').lower()
#             desc = entry.get('description', '').lower()
#             if search_term in name or search_term in desc:
#                 matches.append(entry)
        
#         if not matches:
#             self.print_status(f"No entries found matching '{search_term}'", "info")
#             return
        
#         print(f"\n{Colors.YELLOW}Search Results for '{search_term}':{Colors.RESET}")
#         print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
        
#         for entry in matches:
#             entry_type = entry.get('type', 'unknown')
#             type_icons = {'api_key': '🔑', 'password': '🔒', 'credit_card': '💳', 'secure_note': '📝'}
#             icon = type_icons.get(entry_type, '📄')
            
#             print(f"{icon} {Colors.BOLD}{entry.get('name')}{Colors.RESET}")
#             if entry.get('description'):
#                 print(f"   {Colors.DIM}{entry['description']}{Colors.RESET}")
#             print()
    
#     def run_command(self, command_line):
#         """Parse and execute a command"""
#         if not command_line.strip():
#             return True
        
#         parts = command_line.strip().split()
#         command = parts[0].lower()
#         args = parts[1:] if len(parts) > 1 else []
        
#         # Command mapping
#         commands = {
#             'help': self.cmd_help,
#             'list': self.cmd_list,
#             'get': self.cmd_get,
#             'add': self.cmd_add,
#             'stats': self.cmd_stats,
#             'status': self.cmd_status,
#             'clear': self.cmd_clear,
#             'lock': self.cmd_lock,
#             'search': self.cmd_search,
#             'exit': lambda args: False,
#             'quit': lambda args: False,
#         }
        
#         if command in commands:
#             try:
#                 result = commands[command](args)
#                 return result if result is not None else True
#             except Exception as e:
#                 self.print_error(f"Command failed: {str(e)}")
#                 return True
#         else:
#             self.print_error(f"Unknown command: {command}")
#             self.print_status("Type 'help' for available commands", "info")
#             return True
    
#     def interactive_mode(self):
#         """Run interactive CLI mode"""
#         self.print_banner()
        
#         # Authenticate
#         if not self.authenticate():
#             self.print_status("Authentication failed. Exiting...", "error")
#             return
        
#         print(f"\n{Colors.GREEN}Welcome to Obscura CLI!{Colors.RESET}")
#         self.print_status("Type 'help' for commands or 'exit' to quit", "info")
        
#         # Main command loop
#         while True:
#             try:
#                 prompt = f"{Colors.GREEN}obscura{Colors.RESET}{Colors.DIM}>{Colors.RESET} "
#                 command_line = input(prompt)
                
#                 if not self.run_command(command_line):
#                     break
                    
#             except KeyboardInterrupt:
#                 print(f"\n{Colors.YELLOW}Use 'exit' to quit safely{Colors.RESET}")
#             except EOFError:
#                 print(f"\n{Colors.DIM}Goodbye!{Colors.RESET}")
#                 break
        
#         # Cleanup
#         if self.authenticated:
#             self.vault_manager.lock_vault()
        
#         # Obsidian gradient goodbye message
#         purple2 = '\033[38;2;149;113;221m'  # #9571dd
#         print(f"{Colors.DIM}Session terminated. Stay secure! {purple2}🔐{Colors.RESET}")

# def main():
#     """Main entry point"""
#     parser = argparse.ArgumentParser(
#         description="Obscura CLI - Secure terminal interface for encrypted data management",
#         formatter_class=argparse.RawDescriptionHelpFormatter,
#         epilog="""
# Examples:
#   obscura_cli.py                    # Interactive mode
#   obscura_cli.py list               # List all entries
#   obscura_cli.py get "API Key"      # Get specific entry
#   obscura_cli.py add api_key        # Add new API key
#   obscura_cli.py stats              # Show statistics
#         """
#     )
    
#     parser.add_argument('command', nargs='?', help='Command to execute')
#     parser.add_argument('args', nargs='*', help='Command arguments')
#     parser.add_argument('--no-color', action='store_true', help='Disable colored output')
#     parser.add_argument('--version', action='version', version='Obscura CLI v2.0 - Obsidian Edition')
    
#     args = parser.parse_args()
    
#     # Disable colors if requested or not supported
#     if args.no_color or not sys.stdout.isatty():
#         for attr in dir(Colors):
#             if not attr.startswith('_'):
#                 setattr(Colors, attr, '')
    
#     cli = ObscuraCLI()
    
#     if args.command:
#         # Non-interactive mode
#         if not cli.authenticate():
#             print("Authentication failed")
#             sys.exit(1)
        
#         command_line = f"{args.command} {' '.join(args.args)}"
#         cli.run_command(command_line)
        
#         if cli.authenticated:
#             cli.vault_manager.lock_vault()
#     else:
#         # Interactive mode
#         cli.interactive_mode()

# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
"""
Obscura Vault CLI Wrapper for Electron Integration
This file wraps the existing obscura_final.py functionality for command-line usage
"""

import sys
import json
import os
from pathlib import Path

# Import the existing vault classes
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from obscura_final import ObscuraVaultManager, ObscuraCrypto
except ImportError as e:
    print(json.dumps({"success": False, "error": f"Failed to import vault modules: {str(e)}"}))
    sys.exit(1)

class ObscuraVaultCLI:
    def __init__(self):
        self.vault_manager = ObscuraVaultManager()
        
    def check_vault(self):
        """Check if vault exists and is initialized"""
        try:
            return {
                "success": True,
                "initialized": self.vault_manager.is_vault_initialized()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def initialize_vault(self, master_password):
        """Initialize a new vault with master password"""
        try:
            if self.vault_manager.is_vault_initialized():
                return {"success": False, "error": "Vault already initialized"}
            
            result = self.vault_manager.initialize_vault(master_password)
            if result:
                return {"success": True, "message": "Vault initialized successfully"}
            else:
                return {"success": False, "error": "Failed to initialize vault"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def unlock_vault(self, master_password):
        """Unlock vault with master password"""
        try:
            if not self.vault_manager.is_vault_initialized():
                return {"success": False, "error": "Vault not initialized"}
            
            result = self.vault_manager.unlock_vault(master_password)
            if result:
                return {"success": True, "message": "Vault unlocked successfully"}
            else:
                return {"success": False, "error": "Invalid master password"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def lock_vault(self):
        """Lock the vault"""
        try:
            self.vault_manager.lock_vault()
            return {"success": True, "message": "Vault locked successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def list_entries(self):
        """List all vault entries"""
        try:
            if not self.vault_manager.is_unlocked:
                return {"success": False, "error": "Vault is locked"}
            
            entries = self.vault_manager.list_entries()
            
            # Convert entries to serializable format
            serializable_entries = []
            for entry in entries:
                serializable_entry = {
                    'id': entry['id'],
                    'name': entry['name'],
                    'type': entry['type'],
                    'category': entry['category'],
                    'description': entry['description'],
                    'created': entry['created'],
                    'last_used': entry['last_used'],
                    'usage_count': entry['usage_count']
                    # Note: We don't return the actual encrypted data here for security
                }
                serializable_entries.append(serializable_entry)
            
            return serializable_entries
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def add_entry(self, name, entry_type, data_json, category, description):
        """Add a new entry to the vault"""
        try:
            if not self.vault_manager.is_unlocked:
                return {"success": False, "error": "Vault is locked"}
            
            # Parse the data JSON
            try:
                data = json.loads(data_json)
            except json.JSONDecodeError:
                return {"success": False, "error": "Invalid data format"}
            
            result = self.vault_manager.add_entry(name, entry_type, data, category, description)
            if result:
                return {"success": True, "message": "Entry added successfully"}
            else:
                return {"success": False, "error": "Failed to add entry (name might already exist)"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_entry_data(self, entry_id, field=None):
        """Get decrypted data from an entry"""
        try:
            if not self.vault_manager.is_unlocked:
                return {"success": False, "error": "Vault is locked"}
            
            data = self.vault_manager.get_entry_data(entry_id, field)
            if data is not None:
                return data  # Return the decrypted data directly
            else:
                return {"success": False, "error": "Entry not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def update_entry(self, entry_id, name, entry_type, data_json, category, description):
        """Update an existing entry"""
        try:
            if not self.vault_manager.is_unlocked:
                return {"success": False, "error": "Vault is locked"}
            
            # Parse the data JSON
            try:
                data = json.loads(data_json)
            except json.JSONDecodeError:
                return {"success": False, "error": "Invalid data format"}
            
            result = self.vault_manager.update_entry(entry_id, name, entry_type, data, category, description)
            if result:
                return {"success": True, "message": "Entry updated successfully"}
            else:
                return {"success": False, "error": "Failed to update entry"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def delete_entry(self, entry_id):
        """Delete an entry from the vault"""
        try:
            if not self.vault_manager.is_unlocked:
                return {"success": False, "error": "Vault is locked"}
            
            result = self.vault_manager.delete_entry(entry_id)
            if result:
                return {"success": True, "message": "Entry deleted successfully"}
            else:
                return {"success": False, "error": "Failed to delete entry"}
        except Exception as e:
            return {"success": False, "error": str(e)}

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"success": False, "error": "No command specified"}))
        sys.exit(1)
    
    command = sys.argv[1]
    cli = ObscuraVaultCLI()
    
    try:
        if command == "check":
            result = cli.check_vault()
        elif command == "init":
            if len(sys.argv) < 3:
                result = {"success": False, "error": "Master password required"}
            else:
                result = cli.initialize_vault(sys.argv[2])
        elif command == "unlock":
            if len(sys.argv) < 3:
                result = {"success": False, "error": "Master password required"}
            else:
                result = cli.unlock_vault(sys.argv[2])
        elif command == "lock":
            result = cli.lock_vault()
        elif command == "list":
            result = cli.list_entries()
        elif command == "add":
            if len(sys.argv) < 7:
                result = {"success": False, "error": "Insufficient arguments for add command"}
            else:
                result = cli.add_entry(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        elif command == "get":
            if len(sys.argv) < 3:
                result = {"success": False, "error": "Entry ID required"}
            else:
                field = sys.argv[3] if len(sys.argv) > 3 else None
                result = cli.get_entry_data(sys.argv[2], field)
        elif command == "update":
            if len(sys.argv) < 8:
                result = {"success": False, "error": "Insufficient arguments for update command"}
            else:
                result = cli.update_entry(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
        elif command == "delete":
            if len(sys.argv) < 3:
                result = {"success": False, "error": "Entry ID required"}
            else:
                result = cli.delete_entry(sys.argv[2])
        else:
            result = {"success": False, "error": f"Unknown command: {command}"}
        
        # Output result as JSON
        if isinstance(result, dict):
            print(json.dumps(result))
        else:
            print(result)  # For direct data returns like get_entry_data
            
    except Exception as e:
        print(json.dumps({"success": False, "error": f"Unexpected error: {str(e)}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()