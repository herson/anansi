# 🕸️ Anansi - Advanced Penetration Testing Framework 🕸️

[![CI](https://github.com/herson/anansi/actions/workflows/ci.yml/badge.svg)](https://github.com/herson/anansi/actions/workflows/ci.yml)
[![GitHub License](https://img.shields.io/github/license/herson/anansi)](https://github.com/herson/anansi/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Welcome to **Anansi - The Advanced Penetration Testing Framework**, named after the West African trickster god known for his cleverness. Like Anansi, this framework helps you weave through networks and services with agility, detecting vulnerabilities, automating scans, and exploiting potential security weaknesses.

The framework unifies powerful tools like `nmap`, `metasploit`, and Python’s `python-nmap` to create a robust and extensible penetration testing environment.

---

## 💖 Support the Project

If you find Anansi useful, please consider supporting its development!

[<img src="https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86" width="150" />](https://github.com/sponsors/herson)

---

## 🕸️ Features

Anansi provides the following penetration testing capabilities:

- **Network Scanning**: Discover hosts, open ports, and running services on target networks.
- **Service Enumeration**: Identify potentially vulnerable services and versions running on those hosts.
- **Basic and Advanced Exploitation**: Utilize Metasploit or custom Python scripts.
- **Multithreaded Scanning**: Speed up the scanning process using multithreading.
- **Modular Framework**: Easily extend Anansi’s capabilities by integrating additional tools.
- **Structured Reporting**: Generate reports in JSON or CSV.
- **Configuration Management**: Manage settings via `config.yaml`.
- **Error Handling**: Graceful timeouts and retries.

---

## 🛠️ Tools & Libraries

Anansi is powered by these tools:

- **nmap**: For port scanning and service enumeration.
- **python-nmap**: A Python wrapper for `nmap` to automate scanning.
- **metasploit**: A platform for testing exploits against vulnerable services.
- **Custom Exploitation Modules**: Extend Anansi with custom scripts or other tools.
- **Threading Library**: Use Python’s `concurrent.futures` for multithreaded scans.

---

## 🚀 Installation & Usage

### 1. Prerequisites

Before using Anansi, ensure you have the following:

- **Python 3.x**: The core of the framework is written in Python.
- **nmap**: Used for scanning and service discovery.
- **metasploit-framework**: To run exploitation attempts.

Install the necessary Python packages:

```bash
pip install python-nmap concurrent.futures
```

### 2. Clone the Repository

Clone Anansi to your local machine:

```bash
git clone https://github.com/herson/anansi.git
cd anansi
```

### 3. Run the Framework

Run the main framework script to initiate a scan:

```bash
python3 main.py --target <target_ip_or_range>
```

Example usage:

```bash
python3 main.py --target 192.168.1.0/24
```

This will scan the specified network range, detect open ports, and identify services running on the target hosts.

---

## 📋 Basic Usage

1. **Scanning for Open Ports**: Anansi uses `nmap` to scan for open ports.
   ```bash
   nmap -sS <target_ip>
   ```

2. **Service Enumeration**: After finding open ports, Anansi attempts to identify the services and versions running on each port.
   ```bash
   nmap -sV <target_ip>
   ```

3. **Exploitation**: Based on the identified services, users can use Metasploit or custom scripts to attempt exploitation.

4. **Multithreaded Scanning**: To scan large network ranges faster, you can enable multithreading in the configuration.
   Example:
   ```bash
   python3 main.py --target 192.168.1.0/24 --threads 10
   ```

---

## ⚙️ Configuration

Anansi uses a configuration file to manage scan settings, located in `config.yaml`. Example configuration:

```yaml
default:
  scan_type: "full"
  max_threads: 10
  report_format: "json"
  exclude_ports: [22, 80]
  metasploit_enabled: true
```

Modify this file to suit your testing environment and scan preferences.

---

## 🧪 Running Tests

To ensure the functionality of Anansi, you can run the test suite. Follow these steps:

1. **Navigate to the project root**:
   ```bash
   cd /path/to/anansi
   ```

2. **Set the Python path and run the tests**:
   ```bash
   PYTHONPATH=. python -m unittest discover -s tests/modules
   ```

This command will discover and run all tests located in the `tests/modules` directory.

---

## 🤝 Contributing

Contributions are welcome! We have a set of guidelines to help you get started.

👉 **[Read the Contributing Guidelines](.github/CONTRIBUTING.md)**

Please also review our [Code of Conduct](.github/CODE_OF_CONDUCT.md) before participating.

---

## 📄 License & Changelog

- **License**: [MIT License](LICENSE)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

## 📝 Contact

**Herson Cruz** – [@hersoncruz](https://twitter.com/hersoncruz)

Project Link: [https://github.com/herson/anansi](https://github.com/herson/anansi)
