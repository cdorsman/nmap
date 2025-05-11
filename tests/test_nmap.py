#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

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
            'timeout': 300,
            'timing_template': 3,
            'host_discovery': 'on',
            'scripts': [],
            'service_detection': False,
            'os_detection': False,
            'aggressive_scan': False,
            'privileged': True
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

    def get_sample_output_with_services_and_os(self):
        """Return a sample nmap output with service and OS detection results"""
        return """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.00056s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    Apache httpd 2.4.41
443/tcp open  https   nginx 1.18.0
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.4 - 5.5
Network Distance: 1 hop

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
        self.assertEqual(cmd, ['/usr/bin/nmap', '-sS', '-T3', '-p', '1-1000', '192.168.1.1'])

    def test_build_nmap_command_with_tcp_scan(self):
        """Test building command with TCP scan"""
        self.module.params['scan_type'] = 'tcp'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertEqual(cmd, ['/usr/bin/nmap', '-sT', '-T3', '-p', '1-1000', '192.168.1.1'])

    def test_build_nmap_command_with_output_file(self):
        """Test building command with output file"""
        self.module.params['output_file'] = '/tmp/scan.xml'
        self.module.params['output_format'] = 'xml'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertEqual(cmd, [
            '/usr/bin/nmap', '-sS', '-T3', '-p', '1-1000', '-oX', '/tmp/scan.xml', '192.168.1.1'
        ])

    def test_build_nmap_command_with_arguments(self):
        """Test building command with additional arguments"""
        self.module.params['arguments'] = '-T4 --script=vuln'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertEqual(cmd, [
            '/usr/bin/nmap', '-sS', '-T3', '-p', '1-1000', '-T4', '--script=vuln', '192.168.1.1'
        ])

    def test_build_nmap_command_with_timing_template(self):
        """Test building command with different timing template"""
        # Check default timing (T3)
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-T3', cmd)
        
        # Check aggressive timing (T4)
        self.module.params['timing_template'] = 4
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-T4', cmd)
        
        # Check paranoid timing (T0)
        self.module.params['timing_template'] = 0
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-T0', cmd)

    def test_build_nmap_command_with_host_discovery(self):
        """Test building command with different host discovery options"""
        # Default host discovery behavior (on)
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertNotIn('-Pn', cmd)
        self.assertNotIn('-sn', cmd)
        
        # Skip host discovery (off)
        self.module.params['host_discovery'] = 'off'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-Pn', cmd)
        
        # Ping scan only
        self.module.params['host_discovery'] = 'ping_only'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-sn', cmd)

    def test_build_nmap_command_with_scripts(self):
        """Test building command with script options"""
        # Test with a single script
        self.module.params['scripts'] = ['ssl-heartbleed']
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--script=ssl-heartbleed', cmd)
        
        # Test with multiple scripts
        self.module.params['scripts'] = ['ssl-heartbleed', 'vuln', 'auth']
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--script=ssl-heartbleed,vuln,auth', cmd)

    def test_build_nmap_command_with_service_detection(self):
        """Test building command with service detection enabled"""
        # Default (no service detection)
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertNotIn('-sV', cmd)
        
        # With service detection enabled
        self.module.params['service_detection'] = True
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-sV', cmd)
        
        # With version scan (should not duplicate -sV)
        self.module.params['scan_type'] = 'version'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        # Count occurrences of -sV (should be only one)
        self.assertEqual(cmd.count('-sV'), 1)

    def test_build_nmap_command_with_os_detection(self):
        """Test building command with OS detection enabled"""
        # Default (no OS detection)
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertNotIn('-O', cmd)
        
        # With OS detection enabled
        self.module.params['os_detection'] = True
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-O', cmd)
        
        # With OS scan type (should not duplicate -O)
        self.module.params['scan_type'] = 'os'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        # Count occurrences of -O (should be only one)
        self.assertEqual(cmd.count('-O'), 1)

    def test_build_nmap_command_with_aggressive_scan(self):
        """Test building command with aggressive scanning enabled"""
        # Default (no aggressive scan)
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertNotIn('-A', cmd)
        
        # With aggressive scan enabled
        self.module.params['aggressive_scan'] = True
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-A', cmd)
        
        # Aggressive scan should take precedence over individual options
        self.module.params['service_detection'] = True
        self.module.params['os_detection'] = True
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-A', cmd)
        self.assertNotIn('-sV', cmd)  # Should not be added when aggressive is enabled
        self.assertNotIn('-O', cmd)   # Should not be added when aggressive is enabled

    def test_build_nmap_command_with_privileged(self):
        """Test building command with different privileged options"""
        # Default (privileged mode, using SYN scan)
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-sS', cmd)
        
        # Non-privileged mode, should fall back to TCP scan
        self.module.params['privileged'] = False
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-sT', cmd)
        self.assertNotIn('-sS', cmd)

    def test_build_nmap_command_with_rate_controls(self):
        """Test building command with packet rate controls"""
        # Test min_rate
        self.module.params['min_rate'] = 100
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--min-rate=100', cmd)
        
        # Test max_rate
        self.module.params['max_rate'] = 200
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--min-rate=100', cmd)
        self.assertIn('--max-rate=200', cmd)
        
        # Test max_retries
        self.module.params['max_retries'] = 3
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--max-retries=3', cmd)

    def test_build_nmap_command_with_evasion_techniques(self):
        """Test building command with evasion techniques"""
        # Test source port
        self.module.params['source_port'] = 53
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--source-port=53', cmd)
        
        # Test source address
        self.module.params['source_address'] = '10.0.0.1'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--source=10.0.0.1', cmd)
        
        # Test packet fragmentation
        self.module.params['fragment_packets'] = True
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-f', cmd)
        
        # Test MAC spoofing
        self.module.params['spoof_mac'] = '00:11:22:33:44:55'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--spoof-mac=00:11:22:33:44:55', cmd)

    def test_build_nmap_command_with_additional_options(self):
        """Test building command with additional scan options"""
        # Test DNS resolution options
        self.module.params['dns_resolution'] = 'always'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-n', cmd)
        
        self.module.params['dns_resolution'] = 'never'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--system-dns', cmd)
        
        # Test scan delay
        self.module.params['scan_delay'] = 500
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--scan-delay=500ms', cmd)
        
        # Test interface selection
        self.module.params['interface'] = 'eth0'
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('-e eth0', cmd)
        
        # Test traceroute
        self.module.params['traceroute'] = True
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--traceroute', cmd)
        
        # Test randomize targets
        self.module.params['randomize_targets'] = True
        cmd = nmap.build_nmap_command(self.module, '/usr/bin/nmap')
        self.assertIn('--randomize-hosts', cmd)

    def test_parse_nmap_output(self):
        """Test parsing nmap output"""
        output = self.get_sample_output()
        result = nmap.parse_nmap_output(output)
        self.assertEqual(result, {
            'hosts_count': 1,
            'open_ports': [22, 80, 443]
        })

    def test_parse_nmap_output_with_service_detection(self):
        """Test parsing nmap output with service detection"""
        output = self.get_sample_output_with_services_and_os()
        result = nmap.parse_nmap_output(output, service_detection=True)
        
        # Check that hosts_count and open_ports are still correct
        self.assertEqual(result['hosts_count'], 1)
        self.assertEqual(sorted(result['open_ports']), [22, 80, 443])
        
        # Check that service information was parsed
        self.assertIn('scan_services', result)
        self.assertEqual(result['scan_services']['22'], 'ssh')
        self.assertEqual(result['scan_services']['80'], 'http')
        self.assertEqual(result['scan_services']['443'], 'https')

    def test_parse_nmap_output_with_os_detection(self):
        """Test parsing nmap output with OS detection"""
        output = self.get_sample_output_with_services_and_os()
        result = nmap.parse_nmap_output(output, os_detection=True)
        
        # Check that hosts_count and open_ports are still correct
        self.assertEqual(result['hosts_count'], 1)
        self.assertEqual(sorted(result['open_ports']), [22, 80, 443])
        
        # Check that OS information was parsed
        self.assertIn('os_matches', result)
        self.assertIn('Linux 5.4 - 5.5', result['os_matches'])

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
            'timeout': 300,
            'timing_template': 3,
            'host_discovery': 'on',
            'scripts': [],
            'service_detection': False,
            'os_detection': False,
            'aggressive_scan': False,
            'privileged': True
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
            'timeout': 300,
            'timing_template': 3,
            'host_discovery': 'on',
            'scripts': [],
            'service_detection': False,
            'os_detection': False,
            'aggressive_scan': False,
            'privileged': True
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

    @patch('library.nmap.AnsibleModule')
    def test_main_with_service_and_os_detection(self, mock_ansible_module_class):
        """Test the module with service and OS detection enabled"""
        # Set up module parameters with service and OS detection
        params = {
            'target': '192.168.1.1',
            'scan_type': 'syn',
            'ports': '1-1000',
            'arguments': '',
            'output_file': '',
            'output_format': 'normal',
            'timeout': 300,
            'timing_template': 3,
            'host_discovery': 'on',
            'scripts': [],
            'service_detection': True,
            'os_detection': True,
            'aggressive_scan': False,
            'privileged': True
        }

        # Create a mock for AnsibleModule instance
        mock_module = MagicMock()
        mock_module.params = params
        mock_module.check_mode = False
        # Mock run_command with output that includes services and OS info
        mock_module.run_command.return_value = (0, self.get_sample_output_with_services_and_os(), '')
        # Set up the bin_path mock
        mock_module.get_bin_path.return_value = '/usr/bin/nmap'
        
        # Set up the constructor to return our mock module
        mock_ansible_module_class.return_value = mock_module
        
        # Run the main function
        try:
            nmap.main()
        except SystemExit:
            pass  # This is expected due to how ansible modules exit
        
        # Check assertions for standard fields
        mock_module.exit_json.assert_called_once()
        args, kwargs = mock_module.exit_json.call_args
        self.assertTrue('changed' in kwargs)
        self.assertTrue(kwargs['changed'])
        self.assertTrue('command' in kwargs)
        self.assertTrue('stdout' in kwargs)
        self.assertTrue('rc' in kwargs)
        self.assertTrue('hosts_count' in kwargs)
        self.assertTrue('open_ports' in kwargs)
        
        # Check assertions for service and OS detection fields
        self.assertTrue('scan_services' in kwargs)
        self.assertTrue('os_matches' in kwargs)
        self.assertEqual(kwargs['scan_services']['22'], 'ssh')
        self.assertEqual(kwargs['scan_services']['80'], 'http')
        self.assertEqual(kwargs['scan_services']['443'], 'https')
        self.assertIn('Linux 5.4 - 5.5', kwargs['os_matches'])


class TestNmapModuleAntipatterns(unittest.TestCase):
    """Examples of antipatterns in unit testing"""

    def test_antipattern_implicit_dependencies(self):
        """ANTIPATTERN: Test depends on system state/environment variables"""
        # This test depends on NMAP_PATH environment variable being set
        # which makes the test brittle and unpredictable
        old_path = os.environ.get('NMAP_PATH', '')
        os.environ['NMAP_PATH'] = '/path/to/nmap'
        
        # Test logic that depends on environment variable
        module = MagicMock()
        module.params = {'target': 'localhost'}
        assert nmap.get_nmap_path(module) == '/path/to/nmap'
        
        # Restore environment (often forgotten in antipatterns)
        os.environ['NMAP_PATH'] = old_path
        
    def test_antipattern_side_effects(self):
        """ANTIPATTERN: Test creates side effects that affect other tests"""
        # Creating a temporary file but not cleaning it up
        with open('/tmp/nmap_test_file', 'w') as f:
            f.write('test data')
        
        # No cleanup: this file will remain and could affect other tests
        
    def test_antipattern_nondeterministic(self):
        """ANTIPATTERN: Nondeterministic test that sometimes passes, sometimes fails"""
        # Using random data in tests without setting a seed
        import random
        
        # This will produce different results on each run
        scan_type = random.choice(['tcp', 'syn', 'udp'])
        module = MagicMock()
        module.params = {'target': 'localhost', 'scan_type': scan_type}
        
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        # This assertion might pass or fail depending on the random choice
        self.assertIn('-s' + scan_type[0].upper(), cmd)
        
    def test_antipattern_multiple_assertions(self):
        """ANTIPATTERN: Test with too many unrelated assertions"""
        # This test is trying to test too many things at once
        module = MagicMock()
        module.params = {
            'target': 'localhost',
            'scan_type': 'tcp',
            'ports': '22,80,443',
            'service_detection': True,
            'os_detection': True,
            'aggressive_scan': False,
            'output_file': '/tmp/output.txt',
            'timing_template': 4
        }
        
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        
        # Too many unrelated assertions in one test
        self.assertIn('-sT', cmd)
        self.assertIn('-p', cmd)
        self.assertIn('22,80,443', cmd)
        self.assertIn('-sV', cmd)
        self.assertIn('-O', cmd)
        self.assertNotIn('-A', cmd)
        self.assertIn('-oN', cmd)
        self.assertIn('/tmp/output.txt', cmd)
        self.assertIn('-T4', cmd)
        
    def test_antipattern_hardcoded_paths(self):
        """ANTIPATTERN: Using hardcoded absolute paths"""
        # Hardcoded paths make tests non-portable
        module = MagicMock()
        module.params = {'target': 'localhost', 'output_file': '/home/specific_user/output.xml'}
        
        cmd = nmap.build_nmap_command(module, '/usr/local/bin/nmap')
        self.assertIn('/home/specific_user/output.xml', cmd)
        
    def test_antipattern_sleep(self):
        """ANTIPATTERN: Using sleep() in tests"""
        # Using sleep makes tests slow and unreliable
        module = MagicMock()
        module.run_command.return_value = (0, "nmap output", "")
        
        # Simulating a long-running process with sleep
        import time
        time.sleep(2)  # Slows down tests unnecessarily
        
        result = nmap.main()
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()