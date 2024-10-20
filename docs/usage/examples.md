# Example Use Cases

Here are some example use cases for **Anansi**:

1. **Basic Network Scan**:
   ```bash
   python3 main.py --target 192.168.1.0/24
   ```

2. **Service Enumeration**:
   After scanning the network, use this to enumerate services:
   ```bash
   python3 main.py --enumerate
   ```

3. **Attempting Exploitation**:
   Once enumeration is complete, use:
   ```bash
   python3 main.py --exploit
   ```