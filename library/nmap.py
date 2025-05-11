#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# Import all required modules at the top of the file
import os
import json
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
---
module: nmap
short_description: Run nmap scans on target systems
version_added: "1.0"
description:
    - Runs nmap scans on target systems
    - Can be used to perform various types of port scans and save the output
options:
    target:
        description:
            - The target to scan. Can be a hostname, IP address, network range, etc.
        required: true
        type: str
    scan_type:
        description:
            - The type of scan to perform.
        choices: ['syn', 'tcp', 'udp', 'ping', 'script', 'version', 'os', 'all']
        default: 'syn'
        type: str
    ports:
        description:
            - The ports to scan. Can be a single port, a range of ports, or a list of ports.
            - Specify 'all' to scan all ports, or a range like '1-1000'.
        default: '1-1000'
        type: str
    arguments:
        description:
            - Additional nmap arguments to use
        required: false
        type: str
    output_file:
        description:
            - Path to the output file where scan results should be saved
            - If not specified, only the module output will be returned
        required: false
        type: str
    output_format:
        description:
            - Format of the output file
        choices: ['normal', 'xml', 'json', 'grepable']
        default: 'normal'
        type: str
    timeout:
        description:
            - Timeout for the scan in seconds
        default: 300
        type: int
    timing_template:
        description:
            - Timing template for nmap scan (0-5)
            - Higher values are faster but potentially less reliable
            - 0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane
        type: int
        choices: [0, 1, 2, 3, 4, 5]
        default: 3
    host_discovery:
        description:
            - Control host discovery behavior
            - 'on' performs standard host discovery
            - 'off' skips host discovery (treats all hosts as online)
            - 'ping_only' only performs ping scan without port scanning
        choices: ['on', 'off', 'ping_only']
        default: 'on'
        type: str
    scripts:
        description:
            - List of nmap scripts to run
            - Individual scripts or script categories can be specified
        type: list
        elements: str
        default: []
    service_detection:
        description:
            - Enable or disable service/version detection
        type: bool
        default: false
    os_detection:
        description:
            - Enable or disable OS detection
        type: bool
        default: false
    aggressive_scan:
        description:
            - Enable aggressive scan which enables OS detection, version detection,
              script scanning, and traceroute
            - Equivalent to -A flag in nmap
        type: bool
        default: false
    privileged:
        description:
            - Run scan with elevated privileges (if available)
            - Some scan types like SYN scan require privileged mode
            - If set to false, the module will fall back to a TCP scan if privileges are insufficient
        type: bool
        default: true
    min_rate:
        description:
            - Sets minimum packet rate (packets per second)
            - Can speed up scans but may affect accuracy and stealth
        type: int
        required: false
    max_rate:
        description:
            - Sets maximum packet rate (packets per second)
            - Useful to throttle scans for less network impact
        type: int
        required: false
    max_retries:
        description:
            - Sets maximum number of probe retransmissions
        type: int
        required: false
    source_port:
        description:
            - Specifies source port for scan packets
            - Useful for firewall evasion
        type: int
        required: false
    source_address:
        description:
            - Use specified source address for scan packets
            - Useful for multi-homed systems
        type: str
        required: false
    fragment_packets:
        description:
            - Fragment packets to evade simple packet filters
        type: bool
        default: false
    spoof_mac:
        description:
            - Spoof MAC address for scan packets
            - Can be a vendor name, prefix, or specific MAC
            - Use '0' for random MAC
        type: str
        required: false
    randomize_targets:
        description:
            - Randomize target scan order
            - Good for distributing load across targets
        type: bool
        default: false
    dns_resolution:
        description:
            - Control DNS resolution behavior
        choices: ['default', 'always', 'never']
        default: 'default'
        type: str
    scan_delay:
        description:
            - Add delay between probe packets (milliseconds)
            - Useful for rate limiting and IDS evasion
        type: int
        required: false
    interface:
        description:
            - Specify network interface to use for scanning
        type: str
        required: false
    traceroute:
        description:
            - Enable traceroute functionality
        type: bool
        default: false
requirements:
    - nmap installed on target host
author:
    - "Ansible Automation"
"""

EXAMPLES = r"""
# Basic SYN scan of the top 1000 ports
- name: Scan host with default settings
  nmap:
    target: 192.168.1.1

# TCP connect scan on all ports
- name: Full TCP connect scan
  nmap:
    target: example.com
    scan_type: tcp
    ports: all

# Scan specific ports and save the result to XML file
- name: Scan specific ports and save to file
  nmap:
    target: 10.0.0.0/24
    ports: 22,80,443
    output_file: /tmp/scan_results.xml
    output_format: xml

# Run a script scan
- name: Run script scan
  nmap:
    target: 192.168.1.100
    scan_type: script
    arguments: "--script=vuln"

# Fast scan with aggressive options
- name: Fast aggressive scan
  nmap:
    target: scanme.nmap.org
    aggressive_scan: true
    timing_template: 4

# OS and version detection
- name: OS and service detection
  nmap:
    target: 192.168.1.0/24
    os_detection: true
    service_detection: true
    output_file: /tmp/network_inventory.xml
    output_format: xml

# Run specific NSE scripts
- name: Run specific security scripts
  nmap:
    target: 10.0.0.10
    scripts:
      - ssl-heartbleed
      - vuln
    ports: 443,8443

# Grepable output format for parsing
- name: Use grepable output format
  nmap:
    target: 192.168.1.0/24
    ports: 22,80,443
    output_file: /tmp/scan_results.gnmap
    output_format: grepable
    
# Rate-limited scan for lower network impact
- name: Rate-limited scan
  nmap:
    target: 192.168.0.0/24
    max_rate: 50
    min_rate: 10
    scan_delay: 100
    timing_template: 2
    
# Firewall evasion techniques
- name: Scan with evasion techniques
  nmap:
    target: 10.0.0.5
    fragment_packets: true
    source_port: 53
    source_address: 192.168.1.10
    spoof_mac: "00:11:22:33:44:55"
    
# Network interface selection with traceroute
- name: Scan from specific interface with traceroute
  nmap:
    target: 8.8.8.8
    interface: eth1
    traceroute: true
    
# Skip DNS resolution for faster scanning
- name: Scan without DNS resolution
  nmap:
    target: 10.0.0.0/16
    dns_resolution: never
    randomize_targets: true
    max_retries: 2
"""

RETURN = r"""
command:
    description: The command that was run
    returned: always
    type: str
    sample: "/usr/bin/nmap -sS -p 1-1000 192.168.1.1"
stdout:
    description: The standard output of the nmap command
    returned: always
    type: str
    sample: "Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 10:00 UTC\nNmap scan report for 192.168.1.1\nHost is up (0.00056s latency)."
stderr:
    description: The standard error of the nmap command
    returned: always
    type: str
    sample: ""
rc:
    description: The return code of the nmap command
    returned: always
    type: int
    sample: 0
hosts_count:
    description: The number of hosts that were found
    returned: always
    type: int
    sample: 1
open_ports:
    description: A list of open ports that were found
    returned: always
    type: list
    sample: [22, 80, 443]
scan_services:
    description: Services discovered during version scan (when service_detection is enabled)
    returned: when service_detection is enabled and hosts are found
    type: dict
    sample: {"22": "SSH", "80": "HTTP", "443": "HTTPS"}
os_matches:
    description: OS detection matches (when os_detection is enabled)
    returned: when os_detection is enabled and hosts are found
    type: list
    sample: ["Linux 3.2 - 4.9", "Linux 3.16"]
traceroute_hops:
    description: Network hops discovered through traceroute (when traceroute is enabled)
    returned: when traceroute is enabled and hosts are found
    type: list
    sample: [{"ttl": 1, "ip": "192.168.1.1", "rtt": "0.35ms"}, {"ttl": 2, "ip": "10.0.0.1", "rtt": "1.21ms"}]
packet_rate:
    description: The actual packet rate achieved during the scan (packets per second)
    returned: when min_rate or max_rate is specified
    type: float
    sample: 129.5
scan_stats:
    description: Summary statistics about the scan
    returned: always
    type: dict
    sample: {"start_time": "2025-05-10 10:00:00", "elapsed": "0.20s", "exit_status": "success"}
"""


def get_nmap_path(module):
    """Find the path to the nmap executable"""
    try:
        # Try to find nmap in the PATH
        nmap_path = module.get_bin_path("nmap", required=True)
        return nmap_path
    except Exception as e:
        # Fall back to common system paths if we're in a test environment
        import os
        common_paths = [
            "/usr/bin/nmap", 
            "/usr/local/bin/nmap",
            "/bin/nmap",
            # Add more common paths as needed
        ]
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        
        # If we get here, re-raise the original exception
        raise e


def build_nmap_command(module, nmap_path):
    """Build the nmap command based on the module parameters"""
    target = module.params["target"]
    scan_type = module.params.get("scan_type", "syn")
    ports = module.params.get("ports", "1-1000")
    arguments = module.params.get("arguments", "")
    output_file = module.params.get("output_file", "")
    output_format = module.params.get("output_format", "normal")
    timing_template = module.params.get("timing_template", 3)
    host_discovery = module.params.get("host_discovery", "on")
    scripts = module.params.get("scripts", [])
    service_detection = module.params.get("service_detection", False)
    os_detection = module.params.get("os_detection", False)
    aggressive_scan = module.params.get("aggressive_scan", False)
    privileged = module.params.get("privileged", True)

    # Additional new options
    min_rate = module.params.get("min_rate")
    max_rate = module.params.get("max_rate")
    max_retries = module.params.get("max_retries")
    source_port = module.params.get("source_port")
    source_address = module.params.get("source_address")
    fragment_packets = module.params.get("fragment_packets", False)
    spoof_mac = module.params.get("spoof_mac")
    randomize_targets = module.params.get("randomize_targets", False)
    dns_resolution = module.params.get("dns_resolution", "default")
    scan_delay = module.params.get("scan_delay")
    interface = module.params.get("interface")
    traceroute = module.params.get("traceroute", False)

    # Validate ports format - check for invalid characters that would break nmap
    if ports and any(c in ports for c in "\\`$|&;<>(){}[]"):
        raise ValueError(f"Invalid characters in port specification: {ports}")

    # Start with the base command
    cmd = [nmap_path]

    # Handle aggressive scan option (takes precedence over some others)
    if aggressive_scan:
        cmd.append("-A")
    else:
        # Add scan type if not using aggressive scan
        if scan_type == "syn" and privileged:
            cmd.append("-sS")
        elif scan_type == "syn" and not privileged:
            # Fall back to TCP scan if not privileged
            cmd.append("-sT")
        elif scan_type == "tcp":
            cmd.append("-sT")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "ping":
            cmd.append("-sn")
        elif scan_type == "script":
            cmd.append("-sC")
        elif scan_type == "version":
            cmd.append("-sV")
        elif scan_type == "os":
            cmd.append("-O")
        elif scan_type == "all":
            cmd.extend(["-sS", "-sU", "-sV", "-O"])

        # Add service detection if requested and not already covered by scan type
        if service_detection and scan_type not in ["version", "all"]:
            cmd.append("-sV")

        # Add OS detection if requested and not already covered by scan type
        if os_detection and scan_type not in ["os", "all"]:
            cmd.append("-O")

        # Add traceroute if requested and not part of aggressive scan
        if traceroute:
            cmd.append("--traceroute")

    # Add timing template
    cmd.append(f"-T{timing_template}")

    # Handle host discovery options
    if host_discovery == "off":
        cmd.append("-Pn")
    elif host_discovery == "ping_only":
        cmd.append("-sn")

    # Add packet rate controls
    if min_rate is not None:
        cmd.append(f"--min-rate={min_rate}")
    if max_rate is not None:
        cmd.append(f"--max-rate={max_rate}")

    # Add max retries
    if max_retries is not None:
        cmd.append(f"--max-retries={max_retries}")

    # Add source port
    if source_port is not None:
        cmd.append(f"--source-port={source_port}")

    # Add source address
    if source_address:
        cmd.append(f"--source={source_address}")

    # Add packet fragmentation
    if fragment_packets:
        cmd.append("-f")

    # Add MAC spoofing
    if spoof_mac:
        cmd.append(f"--spoof-mac={spoof_mac}")

    # Add randomize targets
    if randomize_targets:
        cmd.append("--randomize-hosts")

    # Add DNS resolution control
    if dns_resolution == "always":
        cmd.append("-n")
    elif dns_resolution == "never":
        cmd.append("--system-dns")

    # Add scan delay
    if scan_delay is not None:
        cmd.append(f"--scan-delay={scan_delay}ms")

    # Add interface selection
    if interface:
        cmd.append("-e")
        cmd.append(interface)

    # Add ports
    if ports:
        cmd.append("-p")
        cmd.append(ports)

    # Add scripts if specified
    if scripts:
        script_args = "--script=" + ",".join(scripts)
        cmd.append(script_args)

    # Add output file and format
    if output_file:
        if output_format == "xml":
            cmd.append("-oX")
            cmd.append(output_file)
        elif output_format == "json":
            # nmap doesn't have native JSON output, so use XML and we'll convert it
            cmd.append("-oX")
            xml_output = output_file + ".xml"
            cmd.append(xml_output)
        elif output_format == "grepable":
            cmd.append("-oG")
            cmd.append(output_file)
        else:  # normal
            cmd.append("-oN")
            cmd.append(output_file)

    # Add additional arguments
    if arguments:
        cmd.extend(arguments.split())

    # Add target
    cmd.append(target)

    return cmd


def parse_nmap_output(stdout, service_detection=False, os_detection=False):
    """
    Parse nmap output and extract relevant information.

    Args:
        stdout (str): The stdout from the nmap command.
        service_detection (bool): Whether service detection was enabled.
        os_detection (bool): Whether OS detection was enabled.

    Returns:
        dict: A dictionary containing the parsed information.
    """
    result = {"hosts_count": 0, "open_ports": []}

    # Find all open ports
    open_ports = []
    for line in stdout.splitlines():
        if "/tcp" in line or "/udp" in line:
            if "open" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_with_proto = parts[0]
                    port_num = port_with_proto.split("/")[0]
                    try:
                        open_ports.append(int(port_num))
                    except ValueError:
                        pass  # Skip if we can't parse the port as an integer

    # Count hosts that are up
    hosts_count = 0
    for line in stdout.splitlines():
        if "host up" in line.lower():
            hosts_count += 1

    # Extract service information if it was requested
    if service_detection:
        scan_services = {}
        for line in stdout.splitlines():
            if "/tcp" in line or "/udp" in line:
                if "open" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_with_proto = parts[0]
                        port_num = port_with_proto.split("/")[0]
                        service_name = parts[2]
                        scan_services[port_num] = service_name
        result["scan_services"] = scan_services

    # Extract OS information if it was requested
    if os_detection:
        os_matches = []
        capture_os = False
        for line in stdout.splitlines():
            if "OS details:" in line:
                os_details = line.split("OS details:")[1].strip()
                os_matches.append(os_details)
                capture_os = False
            elif "Running:" in line:
                os_running = line.split("Running:")[1].strip()
                os_matches.append(os_running)
            elif "Device type:" in line:
                capture_os = True
            elif capture_os and line.strip() and "Network Distance" not in line:
                os_matches.append(line.strip())

        result["os_matches"] = os_matches

    # Extract traceroute information if present
    traceroute_lines = []
    capture_traceroute = False
    for line in stdout.splitlines():
        if "TRACEROUTE" in line:
            capture_traceroute = True
            continue
        elif capture_traceroute and line.strip():
            if "Nmap done:" in line:
                capture_traceroute = False
                continue
            if "HOP" in line and "RTT" in line and "ADDRESS" in line:
                continue
            traceroute_lines.append(line.strip())

    if traceroute_lines:
        result["traceroute"] = traceroute_lines

    # Set the results
    result["hosts_count"] = hosts_count
    result["open_ports"] = sorted(open_ports)

    return result


def create_json_output(json_file, parsed_info, stdout):
    """
    Create a JSON output file with scan results.

    Args:
        json_file (str): Path to the JSON output file
        parsed_info (dict): Parsed scan information
        stdout (str): Raw nmap output

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create JSON data structure
        json_data = {
            "scan_info": {
                "hosts_count": parsed_info["hosts_count"],
                "open_ports": parsed_info["open_ports"],
                "scan_services": parsed_info.get("scan_services", {}),
                "os_matches": parsed_info.get("os_matches", []),
            },
            "raw_output": stdout,
        }

        # Write JSON to file
        with open(json_file, "w") as f:
            json.dump(json_data, f, indent=2)
        return True
    except Exception:
        # Log errors but don't crash, return False to indicate failure
        return False


def main():
    # Define the module arguments
    module_args = dict(
        target=dict(type="str", required=True),
        scan_type=dict(
            type="str",
            default="syn",
            choices=["syn", "tcp", "udp", "ping", "script", "version", "os", "all"],
        ),
        ports=dict(type="str", default="1-1000"),
        arguments=dict(type="str", required=False),
        output_file=dict(type="str", required=False),
        output_format=dict(
            type="str", default="normal", choices=["normal", "xml", "json", "grepable"]
        ),
        timeout=dict(type="int", default=300),
        timing_template=dict(type="int", choices=[0, 1, 2, 3, 4, 5], default=3),
        host_discovery=dict(
            type="str", choices=["on", "off", "ping_only"], default="on"
        ),
        scripts=dict(type="list", elements="str", default=[]),
        service_detection=dict(type="bool", default=False),
        os_detection=dict(type="bool", default=False),
        aggressive_scan=dict(type="bool", default=False),
        privileged=dict(type="bool", default=True),
        min_rate=dict(type="int", required=False),
        max_rate=dict(type="int", required=False),
        max_retries=dict(type="int", required=False),
        source_port=dict(type="int", required=False),
        source_address=dict(type="str", required=False),
        fragment_packets=dict(type="bool", default=False),
        spoof_mac=dict(type="str", required=False),
        randomize_targets=dict(type="bool", default=False),
        dns_resolution=dict(
            type="str", choices=["default", "always", "never"], default="default"
        ),
        scan_delay=dict(type="int", required=False),
        interface=dict(type="str", required=False),
        traceroute=dict(type="bool", default=False),
    )

    # Create the module
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # Check if running in check mode
    if module.check_mode:
        module.exit_json(changed=False, msg="Module would run nmap scan against target")

    # Get the nmap executable path
    nmap_path = get_nmap_path(module)

    # Build the command
    cmd = build_nmap_command(module, nmap_path)

    # Run the command
    rc, stdout, stderr = module.run_command(cmd, use_unsafe_shell=False)

    # Process the results
    result = {
        "changed": True,
        "command": " ".join(cmd),
        "stdout": stdout,
        "stderr": stderr,
        "rc": rc,
    }

    # Parse the output for additional information
    parsed_info = parse_nmap_output(
        stdout, module.params["service_detection"], module.params["os_detection"]
    )
    result.update(parsed_info)

    # Handle JSON output if requested
    if (
        module.params.get("output_file")
        and module.params.get("output_format") == "json"
        and rc == 0
    ):
        # The temporary XML file
        xml_file = module.params["output_file"] + ".xml"
        # The final JSON file
        json_file = module.params["output_file"]

        # Create JSON file with scan results
        success = create_json_output(json_file, parsed_info, stdout)
        if not success:
            module.fail_json(msg="Failed to create JSON output file", **result)

        # Clean up the temporary XML file
        if os.path.exists(xml_file):
            os.remove(xml_file)

    # Check if the command failed
    if rc != 0:
        module.fail_json(msg="Nmap scan failed", **result)

    # Return the result
    module.exit_json(**result)


if __name__ == "__main__":
    main()
