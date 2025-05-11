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

There are several ways to use this NMap module in your Ansible projects:

### Method 1: Local Module Installation

The simplest approach for a single project:

1. Create a `library` directory in your Ansible project (if it doesn't exist):
   ```bash
   mkdir -p /path/to/your/ansible/project/library
   ```

2. Copy the module to your project's library directory:
   ```bash
   cp library/nmap.py /path/to/your/ansible/project/library/
   ```

### Method 2: Using Environment Variables

For temporary use across multiple projects:

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/ansible-nmap.git
   ```

2. Set the `ANSIBLE_LIBRARY` environment variable to point to the library directory:
   ```bash
   export ANSIBLE_LIBRARY=/path/to/ansible-nmap/library:$ANSIBLE_LIBRARY
   ```

### Method 3: Configuration File

For persistent use across multiple projects:

1. Clone this repository to a permanent location:
   ```bash
   git clone https://github.com/yourusername/ansible-nmap.git /opt/ansible-nmap
   ```

2. Add the module path to your Ansible configuration file (`ansible.cfg`):
   ```ini
   [defaults]
   library = /opt/ansible-nmap/library:~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules
   ```

### Method 4: Ansible Galaxy Collection (Coming Soon)

We're working on packaging this as an Ansible Galaxy collection for easier distribution and installation.

### Prerequisites Installation

Ensure NMap is installed on the target systems:

#### For Debian/Ubuntu:
```bash
sudo apt update
sudo apt install nmap
```

#### For RHEL/CentOS/Fedora:
```bash
sudo dnf install nmap
# or
sudo yum install nmap
```

#### For macOS:
```bash
brew install nmap
```

#### Verifying Installation

To verify that NMap is installed correctly:
```bash
nmap --version
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

#### Test Structure

The test suite is organized into several categories:

- **Unit Tests** (`test_nmap.py`): Tests individual functions in isolation
- **Smoke Tests** (`test_nmap_smoke.py`): Quick basic tests that verify core functionality
- **Functional Tests** (`test_nmap_functional.py`): Tests that verify module functionality
- **Integration Tests** (`test_nmap_integration.py`): Tests that verify integration with the system
- **Regression Tests** (`test_nmap_regression.py`): Tests that verify fixes for specific bugs

#### Expected Test Failures

The test suite includes several "antipattern" test classes that demonstrate bad testing practices. These tests are **intentionally designed to fail** as educational examples of what not to do in tests:

- `TestNmapModuleAntipatterns`: Demonstrates bad unit testing practices
- `TestNmapFunctionalAntipatterns`: Demonstrates bad functional testing practices
- `TestNmapSmokeAntipatterns`: Demonstrates bad smoke testing practices

When running the test suite, expect these antipattern tests to fail. This is normal and by design. The real tests should pass successfully.

If you want to run only the actual tests (without the antipatterns), use:

```
python -m pytest -k "not Antipatterns"
```

## License

MIT

## Author

Your Name <your.email@example.com>