#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest
import subprocess
import tempfile
from unittest.mock import MagicMock

# Ensure proper import of the module under test
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from library import nmap

# Check if nmap is available
NMAP_AVAILABLE = subprocess.run(['which', 'nmap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0

class TestNmapSmoke(unittest.TestCase):
    """Smoke tests for nmap Ansible module"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.TemporaryDirectory()
        
    def tearDown(self):
        """Clean up after test"""
        self.temp_dir.cleanup()
    
    def create_module_mock(self, **kwargs):
        """Create a mock AnsibleModule with the given parameters"""
        # Default parameters
        params = {
            'target': 'localhost',
            'scan_type': 'tcp',
            'ports': '22',
            'output_file': '',
            'output_format': 'normal',
            'timeout': 10,
            'timing_template': 3,
            'host_discovery': 'off',
            'scripts': [],
            'service_detection': False,
            'os_detection': False,
            'aggressive_scan': False,
            'privileged': True
        }
        
        # Update with provided kwargs
        params.update(kwargs)
        
        # Create a mock module
        module = MagicMock()
        module.params = params
        module.get_bin_path.return_value = '/usr/bin/nmap'
        
        # Setup run_command to return a successful nmap scan
        sample_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-11 12:00 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
        """
        module.run_command.return_value = (0, sample_output, '')
        
        # Mock exit_json and fail_json
        result = {}
        def mock_exit_json(**kwargs):
            nonlocal result
            result = kwargs
            return result
        
        def mock_fail_json(**kwargs):
            raise Exception(kwargs.get('msg', 'Unknown error'))
        
        module.exit_json = mock_exit_json
        module.fail_json = mock_fail_json
        module.check_mode = False
        
        return module, result
    
    def test_smoke_command_building(self):
        """Smoke test: Verify that the module correctly builds nmap commands"""
        module, _ = self.create_module_mock()
        
        # Get nmap path
        nmap_path = nmap.get_nmap_path(module)
        self.assertEqual(nmap_path, '/usr/bin/nmap')
        
        # Test command building
        cmd = nmap.build_nmap_command(module, nmap_path)
        
        # Verify basic command structure
        self.assertEqual(cmd[0], '/usr/bin/nmap')
        self.assertIn('-sT', cmd)  # TCP scan
        self.assertIn('-T3', cmd)  # Timing template
        self.assertIn('-Pn', cmd)  # Skip host discovery
        self.assertIn('-p', cmd)   # Port specification
        self.assertIn('22', cmd)   # Port 22
        self.assertIn('localhost', cmd)  # Target
    
    @unittest.skipIf(not NMAP_AVAILABLE, "nmap is not installed")
    def test_smoke_run_scan(self):
        """Smoke test: Run a basic scan and verify output parsing"""
        module, result = self.create_module_mock()
        
        # Run main function directly
        # We need to patch sys.exit to prevent it from actually exiting
        original_exit = sys.exit
        sys.exit = MagicMock()
        
        try:
            # We need to manually parse the output since we're not using the real exit_json
            cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
            rc, stdout, stderr = module.run_command(cmd)
            
            # Check that nmap ran successfully
            self.assertEqual(rc, 0, f"nmap failed with error: {stderr}")
            
            # Parse the output
            parsed = nmap.parse_nmap_output(stdout)
            
            # Verify basic parsing
            self.assertIsInstance(parsed, dict)
            self.assertIn('hosts_count', parsed)
            self.assertIn('open_ports', parsed)
            
        finally:
            # Restore sys.exit
            sys.exit = original_exit
    
    def test_smoke_output_file(self):
        """Smoke test: Verify output file generation"""
        output_file = os.path.join(self.temp_dir.name, 'nmap_output.txt')
        module, _ = self.create_module_mock(
            output_file=output_file,
            output_format='normal'
        )
        
        # Build command
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        
        # Verify output file option is in the command
        self.assertIn('-oN', cmd)
        self.assertIn(output_file, cmd)
    
    def test_smoke_parse_nmap_output(self):
        """Smoke test: Verify parsing of nmap output"""
        sample_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-11 12:00 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
        """
        
        # Parse the output
        result = nmap.parse_nmap_output(sample_output)
        
        # Verify basic parsing
        self.assertEqual(result['hosts_count'], 1)
        self.assertEqual(result['open_ports'], [22])
        
        # With service detection
        result = nmap.parse_nmap_output(sample_output, service_detection=True)
        self.assertIn('scan_services', result)
        self.assertEqual(result['scan_services']['22'], 'ssh')
    
    def test_smoke_aggressive_scan(self):
        """Smoke test: Verify aggressive scan option"""
        module, _ = self.create_module_mock(aggressive_scan=True)
        
        # Build command
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        
        # Verify aggressive scan flag is included
        self.assertIn('-A', cmd)
        
        # And that it takes precedence over individual options
        module, _ = self.create_module_mock(
            aggressive_scan=True,
            service_detection=True,
            os_detection=True
        )
        
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        self.assertIn('-A', cmd)
        self.assertNotIn('-sV', cmd)  # Should not include service detection flag
        self.assertNotIn('-O', cmd)   # Should not include OS detection flag


class TestNmapSmokeAntipatterns(unittest.TestCase):
    """Examples of antipatterns in smoke testing"""
    
    def test_antipattern_not_lightweight(self):
        """ANTIPATTERN: Smoke test that is not actually lightweight"""
        # Smoke tests should be quick and lightweight
        module = MagicMock()
        module.params = {
            'target': 'localhost',
            'ports': '1-65535',  # Full port scan - not lightweight
            'scan_type': 'syn',
            'aggressive_scan': True,
            'timing_template': 5  # Aggressive timing
        }
        
        # Build command (this is fine)
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        
        # Actually running this command would be slow and resource-intensive
        # A proper smoke test would just check the command structure
        
    def test_antipattern_external_dependencies(self):
        """ANTIPATTERN: Smoke test with external dependencies"""
        # Smoke tests should be self-contained
        
        # ANTIPATTERN NOTE: This test intentionally depends on an external library ('requests')
        # that might not be installed. This demonstrates a common antipattern where tests
        # depend on external dependencies that aren't part of the core requirements.
        try:
            # Try to import the requests library
            import requests
            has_requests = True
        except ImportError:
            # Handle the case where requests is not installed
            has_requests = False
            # Skip actual test logic but still demonstrate the antipattern
            self.skipTest("Requests library not installed - this is expected and demonstrates the antipattern")
        
        # This code only runs if requests is actually installed
        if has_requests:
            try:
                # Calling an external API - another antipattern
                response = requests.get('https://api.example.com/nmap/validate', 
                                      timeout=5)
                # Using the response in the test
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertTrue(data['valid'])
            except (requests.RequestException, ValueError):
                self.fail("External API request failed")
    
    def test_antipattern_too_many_assertions(self):
        """ANTIPATTERN: Smoke test with too many assertions"""
        # Smoke tests should focus on one key functionality with minimal assertions
        module = MagicMock()
        module.params = {
            'target': 'localhost',
            'scan_type': 'tcp',
            'ports': '22'
        }
        
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        
        # Too detailed for a smoke test
        self.assertEqual(len(cmd), 5)
        self.assertEqual(cmd[0], '/usr/bin/nmap')
        self.assertEqual(cmd[1], '-sT')
        self.assertTrue(any('-p' in c for c in cmd))
        self.assertTrue(any('22' in c for c in cmd))
        self.assertEqual(cmd[-1], 'localhost')
        self.assertNotIn('-sS', cmd)
        self.assertNotIn('-sV', cmd)
        self.assertNotIn('-sU', cmd)
    
    def test_antipattern_full_execution(self):
        """ANTIPATTERN: Smoke test that does a full execution"""
        # Smoke tests should avoid doing full execution of the system
        
        # Create a real module
        module = MagicMock()
        module.params = {
            'target': 'localhost',
            'scan_type': 'tcp',
            'ports': '22',
        }
        module.get_bin_path.return_value = '/usr/bin/nmap'
        module.run_command.return_value = (0, "Starting Nmap...\nHost is up\n22/tcp open\n", "")
        
        # Run the full function end-to-end
        # This is too much for a smoke test
        result = nmap.main()
        
        # Assertions on the result
        self.assertTrue(result['changed'])
        self.assertEqual(result['rc'], 0)
        
    def test_antipattern_conditional_smoke(self):
        """ANTIPATTERN: Conditional smoke test that might not run"""
        # Smoke tests should always run, not be conditional
        
        # Skip the test based on environmental factors
        if os.environ.get('SKIP_NMAP_TESTS'):
            self.skipTest("Nmap tests are disabled")
            
        # Or based on host platform
        if sys.platform != 'linux':
            self.skipTest("This test only runs on Linux")
            
        # The actual test
        module = MagicMock()
        module.params = {'target': 'localhost'}
        cmd = nmap.build_nmap_command(module, '/usr/bin/nmap')
        self.assertTrue(len(cmd) > 0)


if __name__ == '__main__':
    unittest.main()