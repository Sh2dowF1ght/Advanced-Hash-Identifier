# Advanced Hash Identifier & Credential Analyzer

An advanced, standalone Python utility designed to identify, validate, and analyze cryptographic signatures. Unlike basic length-based hash checkers, this tool implements strict regex pattern validation and dynamically extracts **Modular Crypt Format (MCF)** and **PHC String standard** parameters (such as work factors, cost rounds, and memory usage metrics) from complex password hashes.

## Features
* **Multi-Format Verification:** Structural identification of MD5, NTLM, SHA-1, SHA-256, SHA-512, NetNTLMv2, and JSON Web Tokens (JWT).
* **Work Factor Parsing:** Dynamically extracts cost configurations for modern password storage algorithms, including **bcrypt**, **Argon2**, and **Linux SHA-512 Crypt ($6$)**.
* **Strict Format Validation:** Minimizes false positives by verifying complex string components instead of relying purely on character count constraints.
* **Malicious Config Indicators:** Visually flags weak parameters (e.g., bcrypt cost < 10) directly within a clean, terminal-rendered table dashboard.

## Requirements
* Python 3.x
* `rich` CLI formatting library

## Installation & Setup

```bash
# Clone the repository
git clone [https://github.com/Sh2dowF1ght/Advanced-Hash-Identifier.git](https://github.com/Sh2dowF1ght/Advanced-Hash-Identifier.git)

# Navigate into the project directory
cd Advanced-Hash-Identifier

# Install dependencies
pip install rich
