# Ansible NMap Module

An Ansible module for running NMap network scanning operations as part of your automation workflows.

## Features

- Run various types of NMap scans (SYN, TCP, UDP, ping, script, version)
- Configure port ranges to scan
- Support for additional NMap arguments
- Save output in different formats (normal, XML, JSON)
- Structured return data with host counts and open ports
- Comprehensive test suite

## Requirements

- Ansible 2.9 or higher
- Python 3.8 or higher
- NMap installed on the target hosts

## Installation

To use this module in your Ansible project:

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/ansible-nmap.git
   ```

2. Copy the module to your Ansible project:
   ```
   cp ansible-nmap/library/nmap.py /path/to/your/ansible/project/library/
   ```

3. Alternatively, set the `ANSIBLE_LIBRARY` environment variable:
   ```
   export ANSIBLE_LIBRARY=/path/to/ansible-nmap/library
   ```

## Usage

Basic usage in a playbook:

```yaml
- name: Scan web server for common ports
  nmap:
    target: webserver.example.com
    scan_type: syn
    ports: "80,443,8080"
  register: scan_result

- name: Display open ports
  debug:
    var: scan_result.open_ports
```

### Module Parameters

| Parameter | Description | Required | Default | Choices |
|-----------|-------------|----------|---------|---------|
| target | Target to scan (hostname, IP, network range) | yes | | |
| scan_type | Type of scan to perform | no | syn | syn, tcp, udp, ping, script, version |
| ports | Ports to scan | no | 1-1000 | Any valid port spec (e.g., "22,80,443", "1-1000", "all") |
| arguments | Additional NMap arguments | no | | |
| output_file | Path to save scan results | no | | |
| output_format | Format of the output file | no | normal | normal, xml, json |
| timeout | Scan timeout in seconds | no | 300 | |

### Example Playbooks

**Basic SYN scan:**
```yaml
- name: Basic scan of a host
  nmap:
    target: 192.168.1.1
```

**Full TCP scan with specific ports:**
```yaml
- name: Full TCP scan of specific ports
  nmap:
    target: example.com
    scan_type: tcp
    ports: "22,80,443,3306,5432"
    output_file: /tmp/scan_results.xml
    output_format: xml
```

**Script scan for vulnerabilities:**
```yaml
- name: Run vulnerability scan
  nmap:
    target: 10.0.0.0/24
    scan_type: script
    arguments: "--script=vuln"
    timeout: 600
```

## Development

### Setup Development Environment

1. Create a Python virtual environment and install dependencies:
   ```
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Run the tests:
   ```
   python -m pytest
   ```

### Running Tests

The module includes a comprehensive test suite using pytest:

```
source venv/bin/activate
python -m pytest
```

## License

MIT

## Author

Your Name <your.email@example.com>