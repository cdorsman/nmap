#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock, mock_open

# Ensure proper import of the module under test
# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the module - using an absolute import path to avoid confusion
from library import nmap


class TestNmapModule(unittest.TestCase):
    """Test cases for the nmap module"""

    def setUp(self):
        """Set up test environment"""
        self.module = MagicMock()
        self.module.params = {
            'target': '192.168.1.1',
            'scan_type': 'syn',
            'ports': '1-1000',
            'arguments': '',
            'output_file': '',
            'output_format': 'normal',
            'timeout': 300
        }
        self.module.get_bin_path.return_value = '/usr/bin/nmap'
        self.module.run_command.return_value = (0, self.get_sample_output(), '')

    def get_sample_output(self):
        """Return a sample nmap output for testing"""
        return """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.00056s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
        """

    def test_get_nmap_path(self):
        """Test that get_nmap_path returns the correct path"""
        result = nmap.get_nmap_path(self.module)
        self.assertEqual(result, '/usr/bin/nmap')
        self.module.get_bin_path.assert_called_once_with('nmap', required=True)

    def test_build_nmap_command(self):
        """Test that build_nmap_command builds the command correctly"""
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertEqual(cmd, ['/usr/bin/nmap', '-sS', '-p', '1-1000', '192.168.1.1'])

    def test_build_nmap_command_with_tcp_scan(self):
        """Test building command with TCP scan"""
        self.module.params['scan_type'] = 'tcp'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertEqual(cmd, ['/usr/bin/nmap', '-sT', '-p', '1-1000', '192.168.1.1'])

    def test_build_nmap_command_with_output_file(self):
        """Test building command with output file"""
        self.module.params['output_file'] = '/tmp/scan.xml'
        self.module.params['output_format'] = 'xml'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertEqual(cmd, [
            '/usr/bin/nmap', '-sS', '-p', '1-1000', '-oX', '/tmp/scan.xml', '192.168.1.1'
        ])

    def test_build_nmap_command_with_arguments(self):
        """Test building command with additional arguments"""
        self.module.params['arguments'] = '-T4 --script=vuln'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertEqual(cmd, [
            '/usr/bin/nmap', '-sS', '-p', '1-1000', '-T4', '--script=vuln', '192.168.1.1'
        ])

    def test_parse_nmap_output(self):
        """Test parsing nmap output"""
        output = self.get_sample_output()
        result = nmap.parse_nmap_output(output)
        self.assertEqual(result, {
            'hosts_count': 1,
            'open_ports': [22, 80, 443]
        })

    @patch('library.nmap.AnsibleModule')
    def test_main_basic_execution(self, mock_ansible_module_class):
        """Test the basic execution flow of the module"""
        # Set up module parameters
        params = {
            'target': '192.168.1.1',
            'scan_type': 'syn',
            'ports': '1-1000',
            'arguments': '',
            'output_file': '',
            'output_format': 'normal',
            'timeout': 300
        }

        # Create a mock for AnsibleModule instance
        mock_module = MagicMock()
        mock_module.params = params
        mock_module.check_mode = False
        # Mock run_command with successful output
        mock_module.run_command.return_value = (0, self.get_sample_output(), '')
        # Set up the bin_path mock
        mock_module.get_bin_path.return_value = '/usr/bin/nmap'
        
        # Set up the constructor to return our mock module
        mock_ansible_module_class.return_value = mock_module
        
        # Run the main function
        try:
            nmap.main()
        except SystemExit:
            pass  # This is expected due to how ansible modules exit
        
        # Check assertions
        mock_module.exit_json.assert_called_once()
        args, kwargs = mock_module.exit_json.call_args
        self.assertTrue('changed' in kwargs)
        self.assertTrue(kwargs['changed'])
        self.assertTrue('command' in kwargs)
        self.assertTrue('stdout' in kwargs)
        self.assertTrue('rc' in kwargs)
        self.assertTrue('hosts_count' in kwargs)
        self.assertTrue('open_ports' in kwargs)
        self.assertEqual(kwargs['hosts_count'], 1)
        self.assertEqual(sorted(kwargs['open_ports']), [22, 80, 443])

    @patch('library.nmap.AnsibleModule')
    def test_main_failed_execution(self, mock_ansible_module_class):
        """Test the module behavior when nmap execution fails"""
        # Set up module parameters
        params = {
            'target': '192.168.1.1',
            'scan_type': 'syn',
            'ports': '1-1000',
            'arguments': '',
            'output_file': '',
            'output_format': 'normal',
            'timeout': 300
        }

        # Create a mock for AnsibleModule instance
        mock_module = MagicMock()
        mock_module.params = params
        mock_module.check_mode = False
        # Mock run_command with error
        mock_module.run_command.return_value = (1, '', 'Error: nmap failed')
        # Set up the bin_path mock
        mock_module.get_bin_path.return_value = '/usr/bin/nmap'
        
        # Set up the constructor to return our mock module
        mock_ansible_module_class.return_value = mock_module
        
        # Run the main function
        try:
            nmap.main()
        except SystemExit:
            pass  # This is expected due to how ansible modules exit
        
        # Check assertions
        mock_module.fail_json.assert_called_once()
        args, kwargs = mock_module.fail_json.call_args
        self.assertTrue('msg' in kwargs)
        self.assertEqual(kwargs['msg'], "Nmap scan failed")


if __name__ == '__main__':
    unittest.main()