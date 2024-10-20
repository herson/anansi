# Installation Guide

Follow these steps to install and set up the **Anansi Penetration Testing Framework**.

## Prerequisites

- **Python 3.x** installed.
- **nmap** installed:
   ```bash
   sudo apt install nmap
   ```

## Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/herson/anansi.git
   cd anansi
   ```

2. Set up a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Install `nmap` and `metasploit-framework` for the full experience.

4. You’re now ready to run the framework!