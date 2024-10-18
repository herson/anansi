# 🕸️ Anansi - Basic Penetration Testing Framework 🕸️

[![GitHub License](https://img.shields.io/github/license/herson/anansi)](https://github.com/herson/anansi/blob/main/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/herson/anansi?style=social)](https://github.com/herson/anansi/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/herson/anansi)](https://github.com/herson/anansi/issues)

Welcome to **Anansi - The Basic Penetration Testing Framework**, named after the West African trickster god known for his cleverness. Like Anansi, this framework helps you weave through networks and services with agility, detecting vulnerabilities and attempting basic exploitation techniques. The framework brings together powerful tools like `nmap`, `metasploit`, and Python’s `python-nmap` to create a versatile, beginner-friendly penetration testing environment.

---

## 🕸️ Features

Anansi provides the following penetration testing capabilities:

- **Network Scanning**: Discover hosts, open ports, and running services on target networks.
- **Service Enumeration**: Identify potentially vulnerable services and versions running on those hosts.
- **Basic Exploitation**: Utilize Metasploit or custom Python scripts to attempt exploitation of vulnerabilities.
- **Modular Framework**: Easily extend Anansi’s capabilities by integrating additional tools and scripts.
- **Reporting**: Generate structured output of discovered vulnerabilities and exploitation attempts.

---

## 🛠️ Tools & Libraries

Anansi is powered by these tools:

- **nmap**: For port scanning and service enumeration.
- **python-nmap**: A Python wrapper for `nmap` to automate scanning.
- **metasploit**: A platform for testing exploits against vulnerable services.
- **Custom Scripts**: Users can add their own scripts for additional exploitation methods.

---

## 🚀 Installation & Usage

### 1. Prerequisites

Before using Anansi, ensure you have the following:

- **Python 3.x**: The core of the framework is written in Python.
- **nmap**: Used for scanning and service discovery.
- **metasploit-framework**: To run exploitation attempts.

Install the necessary Python packages:

```bash
pip install python-nmap
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
python3 anansi.py --target <target_ip_or_range>
```

Example usage:

```bash
python3 anansi.py --target 192.168.1.0/24
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

---

## 📄 License

Anansi is licensed under the MIT License. See the [LICENSE](https://github.com/herson/anansi/blob/main/LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue to improve Anansi's functionality and scope.

---

## 📝 Contact

**Herson Cruz** – [@hersoncruz](https://twitter.com/hersoncruz)

Project Link: [https://github.com/herson/anansi](https://github.com/herson/anansi)
