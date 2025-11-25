<div align="center">

# 🔐 Text Crypto Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Cryptography](https://img.shields.io/badge/cryptography-41.0%2B-green)](https://cryptography.io/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-A%2B-brightgreen)](SECURITY.md)
[![Tests](https://img.shields.io/badge/tests-passing-success)](tests/)
[![Code Style](https://img.shields.io/badge/code%20style-PEP8-orange)](https://www.python.org/dev/peps/pep-0008/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/text-crypto-tool/graphs/commit-activity)

### 🎯 Enterprise-Grade Text Encryption Suite with Military-Grade Algorithms

**A comprehensive cryptographic toolkit implementing industry-standard encryption algorithms with a focus on security, education, and real-world applicability.**

[Features](#-features) • [Quick Start](#-quick-start) • [Algorithms](#-algorithms) • [Security](#-security) • [Documentation](#-documentation) • [Contributing](#-contributing)

<img src="assets/demo.gif" alt="Demo" width="700"/>

</div>

---

## 🌟 **Why Text Crypto Tool?**

In an era where data breaches cost companies millions and privacy is paramount, understanding and implementing proper encryption is crucial. This project bridges the gap between academic cryptography and practical implementation, providing:

- 🎓 **Educational Value**: Learn cryptography by doing, with detailed explanations
- 🔒 **Production-Ready Code**: Following NIST standards and security best practices
- 🚀 **Performance Optimized**: Benchmarked algorithms with performance metrics
- 🛡️ **Security First**: Authenticated encryption, tamper detection, and secure key management
- 📊 **Comparative Analysis**: Understand why AES replaced DES, when to use RSA vs symmetric encryption

---

## ✨ **Features**

### 🔐 **Cryptographic Capabilities**

| Algorithm | Mode | Security Level | Use Case | Status |
|-----------|------|---------------|----------|---------|
| **AES-256** | GCM | 🛡️ Military Grade | Bulk encryption, Files, Messages | ✅ Production Ready |
| **RSA-2048/4096** | OAEP | 🔒 High | Key exchange, Digital signatures | ✅ Production Ready |
| **Hybrid** | RSA+AES | 🚀 Optimal | Large files, Secure communication | ✅ Production Ready |
| **DES** | CBC | ⚠️ Obsolete | Educational only | ⚠️ Legacy Demo |

### 🎯 **Core Features**

- **🔄 Hybrid Encryption System**: Combines RSA's security with AES's speed
- **✅ Authenticated Encryption (AEAD)**: Ensures both confidentiality and integrity
- **🔑 Advanced Key Management**: Secure generation, storage, rotation, and destruction
- **🛡️ Tamper Detection**: Cryptographic verification of data integrity
- **🎲 Cryptographically Secure RNG**: For keys, nonces, and IVs
- **📊 Performance Benchmarking**: Compare algorithm speeds and security
- **🧪 Comprehensive Test Suite**: Unit, integration, and security tests
- **🎨 Interactive CLI**: User-friendly interface with colored output
- **📁 Multiple Export Formats**: JSON, Base64, PEM for keys

### 🔬 **Security Features**

```python
✅ NIST-Compliant Algorithms      ✅ Constant-Time Operations
✅ Side-Channel Attack Protection  ✅ Memory-Safe Key Handling
✅ OAEP Padding (RSA)             ✅ GCM Authentication (AES)
✅ Unique Nonce Generation        ✅ Secure Key Derivation
✅ Anti-Tampering Mechanisms      ✅ Timing Attack Mitigation
