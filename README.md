# 🕸️ Anansi - Advanced Penetration Testing Framework 🕸️

[![GitHub License](https://img.shields.io/github/license/herson/anansi)](https://github.com/herson/anansi/blob/main/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/herson/anansi?style=social)](https://github.com/herson/anansi/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/herson/anansi)](https://github.com/herson/anansi/issues)

Welcome to **Anansi - The Advanced Penetration Testing Framework**, named after the West African trickster god known for his cleverness. Like Anansi, this framework helps you weave through networks and services with agility, detecting vulnerabilities, automating scans, and exploiting potential security weaknesses. The framework unifies powerful tools like `nmap`, `metasploit`, and Python’s `python-nmap` to create a robust and extensible penetration testing environment.

---

## 🕸️ Features

Anansi provides the following penetration testing capabilities:

- **Network Scanning**: Discover hosts, open ports, and running services on target networks.
- **Service Enumeration**: Identify potentially vulnerable services and versions running on those hosts.
- **Basic and Advanced Exploitation**: Utilize Metasploit or custom Python scripts to attempt basic or advanced exploitation.
- **Multithreaded Scanning**: Speed up the scanning process using multithreading for large networks.
- **Modular Framework**: Easily extend Anansi’s capabilities by integrating additional tools, modules, and scripts.
- **Structured Reporting**: Generate detailed reports in JSON or CSV format for discovered vulnerabilities, exploits, and remediation attempts.
- **Configuration Management**: Manage scanning configurations via a central config file (`config.yaml`) to streamline settings for repeated testing.
- **Error Handling & Timeouts**: Handle common network issues with graceful timeouts and retries during scanning.

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

## 📄 License

Anansi is licensed under the MIT License. See the [LICENSE](https://github.com/herson/anansi/blob/main/LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue to improve Anansi's functionality and scope.

---

## 📝 Contact

**Herson Cruz** – [@hersoncruz](https://twitter.com/hersoncruz)

Project Link: [https://github.com/herson/anansi](https://github.com/herson/anansi)
