# 🔐 OBSCURA - The Ultimate Secure Vault

> **Military-grade encryption meets beautiful design. Your secrets, absolutely secure.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: AES-256](https://img.shields.io/badge/Security-AES--256--GCM-green.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![GUI: CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-purple.svg)](https://github.com/TomSchimansky/CustomTkinter)

**Obscura** is a cutting-edge, locally-encrypted password manager and secure vault that puts your privacy first. With zero cloud dependencies and military-grade encryption, your sensitive data never leaves your device.

## ✨ Why Obscura?

- 🔒 **Zero-Knowledge Architecture** - Your master password never touches our servers
- 🛡️ **AES-256-GCM Encryption** - Same standard used by governments and militaries
- 🎨 **Beautiful Dark UI** - Cyberpunk-inspired design with Matrix-style animations
- 💾 **Fully Offline** - No internet required, no data collection, ever
- 🚀 **Lightning Fast** - Instant access to your encrypted vault
- 🔐 **Auto-Lock Protection** - Automatic vault locking after 30 minutes of inactivity

## 🎯 Perfect For

- **Developers** storing API keys, database credentials, and SSH keys
- **Professionals** managing work passwords and secure notes
- **Privacy Enthusiasts** who want complete control over their data
- **Indian Users** with specialized banking support (SBI, HDFC, ICICI, Axis)
- **Anyone** who values security and beautiful user interfaces

## 🚀 Quick Start

### 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/obscura-vault.git
cd obscura-vault

# Install dependencies
pip install -r requirements.txt

# Launch Obscura
python obscura_final.py
```

### 🔧 Dependencies

```
customtkinter>=5.2.0
cryptography>=41.0.0
argon2-cffi>=23.1.0
pyperclip>=1.8.2
```

## 🎭 Features Overview

### 🔐 **Secure Entry Types**
- **🔑 API Keys** - Store OpenAI, Stripe, AWS, and other API credentials
- **🔒 Passwords** - Website logins with username/password combinations
- **💳 Credit Cards** - Encrypted card details with CVV protection
- **💰 Debit Cards** - Bank cards with PIN and expiry date storage
- **🏦 Banking Details** - Complete Indian banking support with UPI, IFSC, and transaction passwords
- **📝 Secure Notes** - Encrypted text storage for sensitive information

### 🛡️ **Advanced Security Features**
- **Argon2 Password Hashing** - Memory-hard function resistant to GPU attacks
- **PBKDF2 Key Derivation** - 100,000 iterations for maximum security
- **Salt-Based Encryption** - Unique salt for every encryption operation
- **Memory Clearing** - Automatic key cleanup after use
- **Authentication Tags** - GCM mode ensures data integrity

### 🎨 **User Experience**
- **Matrix Rain Animation** - Stunning cyberpunk-style background
- **Smart Search & Filtering** - Find entries instantly by name, type, or category
- **One-Click Copy** - Secure clipboard with auto-clear after 30 seconds
- **Auto-Lock Timer** - Vault automatically locks after inactivity
- **Personalized Interface** - Custom welcome messages and branding

## 🔧 Usage Guide

### 🆕 First Time Setup

1. **Launch Obscura** - Run `python obscura_final.py`
2. **Create Master Password** - Choose a strong password (8+ characters)
3. **Start Adding Entries** - Use the colored buttons to add different types

### 📱 Managing Entries

#### Adding API Keys
```
🔑 API Key Button → Fill Details → 🔐 Add & Encrypt
- Name: "OpenAI GPT-4 Key"
- Category: "OpenAI"
- API Key: "sk-..."
- Description: "Production API key for ChatGPT integration"
```

#### Banking Details (Indian Banks)
```
🏦 Banking Button → Complete Form
- Bank: "State Bank of India"
- Account: "Your account number"
- IFSC: "SBIN0001234"
- Login Password: "Net banking password"
- Transaction Password: "MPIN/Transaction password"
- UPI PIN: "6-digit UPI PIN"
```

### 🔍 Search & Organization

- **Search**: Type in the search box to find entries instantly
- **Filter by Type**: Use dropdown to show only specific entry types
- **Filter by Category**: Organize by OpenAI, Banking, Personal, etc.
- **Smart Categories**: Pre-configured for Indian banks and popular services

## 🏗️ Architecture

### 🔐 Encryption Flow
```
Your Data → AES-256-GCM → Encrypted Package → Local Storage
     ↑              ↑
Master Password → Argon2 Hash → PBKDF2 Key Derivation
```

### 📁 File Structure
```
.obscura/
├── vault.enc     # Your encrypted data
└── config.json   # Vault configuration (no sensitive data)
```

### 🛡️ Security Layers

1. **Master Password** → Argon2 hashing with salt
2. **Key Derivation** → PBKDF2 with 100,000 iterations
3. **Encryption** → AES-256 in GCM mode
4. **Authentication** → GCM auth tags prevent tampering
5. **Memory Protection** → Keys zeroed after use

## 🌟 Advanced Features

### ⏰ Auto-Lock Protection
```python
# Vault automatically locks after 30 minutes
# Customizable in source code
AUTO_LOCK_TIMEOUT = 1800000  # 30 minutes in milliseconds
```

### 📋 Secure Clipboard
- Copied data auto-clears after 30 seconds
- Only the specific field you need gets copied
- No clipboard history retention

### 🎨 Customization
- **Matrix Effect**: Modify animation speed and characters
- **Color Themes**: Change accent colors in the source
- **Categories**: Add your own custom categories
- **Auto-Lock Timer**: Adjust timeout duration

## 🛠️ Development

### 🏗️ Building from Source

```bash
# Clone and setup development environment
git clone https://github.com/yourusername/obscura-vault.git
cd obscura-vault

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python obscura_final.py
```

### 🧪 Testing Your Installation

```bash
# Test encryption/decryption
python -c "
from obscura_final import ObscuraCrypto
crypto = ObscuraCrypto()
encrypted = crypto.encrypt_data('test', 'password123')
decrypted = crypto.decrypt_data(encrypted, 'password123')
print('✅ Encryption test passed!' if decrypted == 'test' else '❌ Test failed')
"
```

## 📋 Requirements

- **Python 3.8+**
- **Operating System**: Windows 10+, macOS 10.15+, Linux (any modern distro)
- **Memory**: 4GB RAM recommended
- **Storage**: 50MB for application + your encrypted data

## 🔒 Security Considerations

### ✅ What's Secure
- All data encrypted with AES-256-GCM
- Master password never stored in plain text
- Memory cleared after cryptographic operations
- No network connections required
- Vault auto-locks on inactivity

### ⚠️ Security Notes
- **Master Password**: Choose a strong, unique password
- **Backup**: Keep secure backups of your `.obscura` folder
- **Physical Security**: Protect your device from unauthorized access
- **Updates**: Keep Python and dependencies updated

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 Bug Reports
- Use the GitHub Issues tab
- Include your Python version and OS
- Describe steps to reproduce

### 💡 Feature Requests
- Check existing issues first
- Explain your use case
- Consider security implications

### 🔧 Pull Requests
1. Fork the repository
2. Create a feature branch
3. Add tests if applicable
4. Update documentation
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CustomTkinter** - For the beautiful modern GUI framework
- **Cryptography Library** - For robust encryption implementations
- **Argon2** - For secure password hashing
- **Matrix Digital Rain** - Inspiration for the cyberpunk aesthetic

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/hammadmalik17/Obscura/issues)
- 📧 **Security Issues**: Email drhammadmalik2020@gmail.com

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/obscura-vault&type=Date)](https://star-history.com/#yourusername/obscura-vault&Date)

---

<div align="center">

**🔐 Your secrets deserve military-grade protection. Welcome to Obscura.**

[⬆️ Back to Top](#-obscura---the-ultimate-secure-vault)

</div>