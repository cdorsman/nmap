#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

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
        choices: ['syn', 'tcp', 'udp', 'ping', 'script', 'version']
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
        choices: ['normal', 'xml', 'json']
        default: 'normal'
        type: str
    timeout:
        description:
            - Timeout for the scan in seconds
        default: 300
        type: int
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
"""

import os
import re
import json
from ansible.module_utils.basic import AnsibleModule


def get_nmap_path(module):
    """Find the path to the nmap executable"""
    nmap_path = module.get_bin_path('nmap', required=True)
    return nmap_path


def build_nmap_command(module, nmap_path):
    """Build the nmap command based on the module parameters"""
    target = module.params['target']
    scan_type = module.params['scan_type']
    ports = module.params['ports']
    arguments = module.params.get('arguments', '')
    output_file = module.params.get('output_file', '')
    output_format = module.params['output_format']
    
    # Start with the base command
    cmd = [nmap_path]
    
    # Add scan type
    if scan_type == 'syn':
        cmd.append('-sS')
    elif scan_type == 'tcp':
        cmd.append('-sT')
    elif scan_type == 'udp':
        cmd.append('-sU')
    elif scan_type == 'ping':
        cmd.append('-sn')
    elif scan_type == 'script':
        cmd.append('-sC')
    elif scan_type == 'version':
        cmd.append('-sV')
    
    # Add ports
    if ports:
        cmd.append('-p')
        cmd.append(ports)
    
    # Add output file and format
    if output_file:
        if output_format == 'xml':
            cmd.append('-oX')
            cmd.append(output_file)
        elif output_format == 'json':
            # nmap doesn't have native JSON output, so use XML and we'll convert it
            cmd.append('-oX')
            xml_output = output_file + '.xml'
            cmd.append(xml_output)
        else:  # normal
            cmd.append('-oN')
            cmd.append(output_file)
    
    # Add additional arguments
    if arguments:
        cmd.extend(arguments.split())
    
    # Add target
    cmd.append(target)
    
    return cmd


def parse_nmap_output(output):
    """Parse the output from nmap to get information about open ports"""
    open_ports = []
    host_count = 0
    
    # Count hosts
    host_matches = re.findall(r'Nmap scan report for', output)
    if host_matches:
        host_count = len(host_matches)
    
    # Find open ports
    port_matches = re.findall(r'(\d+)/[a-z]+ +open', output)
    if port_matches:
        open_ports = [int(port) for port in port_matches]
    
    return {
        'hosts_count': host_count,
        'open_ports': open_ports
    }


def main():
    # Define the module arguments
    module_args = dict(
        target=dict(type='str', required=True),
        scan_type=dict(
            type='str',
            default='syn',
            choices=['syn', 'tcp', 'udp', 'ping', 'script', 'version']
        ),
        ports=dict(type='str', default='1-1000'),
        arguments=dict(type='str', required=False),
        output_file=dict(type='str', required=False),
        output_format=dict(
            type='str',
            default='normal',
            choices=['normal', 'xml', 'json']
        ),
        timeout=dict(type='int', default=300),
    )
    
    # Create the module
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    
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
        'changed': True,
        'command': ' '.join(cmd),
        'stdout': stdout,
        'stderr': stderr,
        'rc': rc,
    }
    
    # Parse the output for additional information
    parsed_info = parse_nmap_output(stdout)
    result.update(parsed_info)
    
    # Handle JSON output if requested
    if (module.params.get('output_file') and 
        module.params.get('output_format') == 'json' and
        rc == 0):
        try:
            # The temporary XML file
            xml_file = module.params['output_file'] + '.xml'
            # The final JSON file
            json_file = module.params['output_file']
            
            # Here we would convert the XML to JSON
            # This is a simplified version - in a real module you'd want to use
            # a proper XML parser to convert to JSON
            
            # For now, let's just create a simple JSON file with the parsed results
            with open(json_file, 'w') as f:
                json.dump({
                    'scan_info': {
                        'hosts_count': parsed_info['hosts_count'],
                        'open_ports': parsed_info['open_ports']
                    },
                    'raw_output': stdout
                }, f, indent=2)
            
            # Clean up the temporary XML file
            if os.path.exists(xml_file):
                os.remove(xml_file)
                
        except Exception as e:
            module.fail_json(msg=f"Failed to create JSON output: {str(e)}")
    
    # Check if the command failed
    if rc != 0:
        module.fail_json(msg="Nmap scan failed", **result)
    
    # Return the result
    module.exit_json(**result)


if __name__ == '__main__':
    main()