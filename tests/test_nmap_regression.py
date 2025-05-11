#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
from library import nmap


class TestNmapRegression(unittest.TestCase):
    """Regression tests for the nmap module"""

    def setUp(self):
        """Set up test environment"""
        self.module = MagicMock()
        # Set defaults for all module parameters
        self.module.params = {
            "target": "192.168.1.1",
            "scan_type": "syn",
            "ports": "1-1000",
            "arguments": "",
            "output_file": "",
            "output_format": "normal",
            "timeout": 300,
            "timing_template": 3,
            "host_discovery": "on",
            "scripts": [],
            "service_detection": False,
            "os_detection": False,
            "aggressive_scan": False,
            "privileged": True,
            "min_rate": None,
            "max_rate": None,
            "max_retries": None,
            "source_port": None,
            "source_address": None,
            "fragment_packets": False,
            "spoof_mac": None,
            "randomize_targets": False,
            "dns_resolution": "default",
            "scan_delay": None,
            "interface": None,
            "traceroute": False,
        }
        self.module.get_bin_path.return_value = "/usr/bin/nmap"
        self.module.run_command.return_value = (0, self.get_sample_output(), "")

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

    def get_sample_output_with_services(self):
        """Return a sample nmap output with service information"""
        return """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.00056s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    Apache httpd 2.4.41
443/tcp open  https  nginx 1.18.0

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
        """

    def get_sample_output_with_os_info(self):
        """Return a sample nmap output with OS detection information"""
        return """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.00056s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp open  https
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.4 - 5.5
Network Distance: 1 hop

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
        """

    def get_sample_output_with_traceroute(self):
        """Return a sample nmap output with traceroute information"""
        return """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.00056s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp open  https

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   0.35ms  192.168.0.1
2   1.21ms  10.0.0.1
3   4.62ms  172.16.0.1

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
        """

    def test_default_scan_parameters(self):
        """Test that the default scan parameters produce the expected command"""
        cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
        # Default should be a SYN scan with default timing and port range
        expected_cmd = ["/usr/bin/nmap", "-sS", "-T3", "-p", "1-1000", "192.168.1.1"]
        self.assertEqual(cmd, expected_cmd)

    def test_scan_types(self):
        """Test that different scan types produce the expected flags"""
        scan_types = [
            ("syn", "-sS"),
            ("tcp", "-sT"),
            ("udp", "-sU"),
            ("ping", "-sn"),
            ("script", "-sC"),
            ("version", "-sV"),
            ("os", "-O"),
            ("all", "-sS"),  # all includes multiple flags
        ]

        for scan_type, expected_flag in scan_types:
            with self.subTest(scan_type=scan_type):
                self.module.params["scan_type"] = scan_type
                cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
                self.assertIn(expected_flag, cmd)
                if scan_type == "all":
                    self.assertIn("-sS", cmd)
                    self.assertIn("-sU", cmd)
                    self.assertIn("-sV", cmd)
                    self.assertIn("-O", cmd)

    def test_timing_templates(self):
        """Test that different timing templates produce the expected flags"""
        timing_templates = [
            (0, "-T0"),
            (1, "-T1"),
            (2, "-T2"),
            (3, "-T3"),
            (4, "-T4"),
            (5, "-T5"),
        ]

        for timing, expected_timing in timing_templates:
            with self.subTest(timing=timing):
                self.module.params["timing_template"] = timing
                cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
                self.assertIn(expected_timing, cmd)

    def test_host_discovery(self):
        """Test that host discovery options work correctly"""
        discovery_options = [("on", None), ("off", "-Pn"), ("ping_only", "-sn")]

        for discovery, expected_flag in discovery_options:
            with self.subTest(discovery=discovery):
                self.module.params["host_discovery"] = discovery
                cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
                if expected_flag:
                    self.assertIn(expected_flag, cmd)
                else:
                    # For 'on', neither -Pn nor -sn should be present
                    self.assertNotIn("-Pn", cmd)
                    # Only assert -sn not present if scan_type is not 'ping'
                    if self.module.params["scan_type"] != "ping":
                        self.assertNotIn("-sn", cmd)

    def test_privileged_fallback(self):
        """Test that unprivileged mode falls back to TCP scan"""
        # Set SYN scan with privileged=False
        self.module.params["scan_type"] = "syn"
        self.module.params["privileged"] = False
        cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")

        # Should fall back to TCP scan
        self.assertNotIn("-sS", cmd)
        self.assertIn("-sT", cmd)

    def test_output_formats(self):
        """Test that output formats produce the expected flags"""
        output_formats = [
            ("normal", "-oN"),
            ("xml", "-oX"),
            ("json", "-oX"),  # JSON uses XML temporarily
            ("grepable", "-oG"),
        ]

        for output_format, expected_flag in output_formats:
            with self.subTest(output_format=output_format):
                self.module.params["output_format"] = output_format
                self.module.params["output_file"] = "/tmp/nmap_output"
                cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
                self.assertIn(expected_flag, cmd)

    def test_evasion_techniques(self):
        """Test that evasion techniques produce the expected flags"""
        self.module.params.update(
            {
                "fragment_packets": True,
                "source_port": 53,
                "source_address": "10.0.0.1",
                "spoof_mac": "00:11:22:33:44:55",
            }
        )
        cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
        self.assertIn("-f", cmd)
        self.assertIn("--source-port=53", cmd)
        self.assertIn("--source=10.0.0.1", cmd)  # Fixed source address
        self.assertIn("--spoof-mac=00:11:22:33:44:55", cmd)

    def test_combined_scan_features(self):
        """Test combining multiple scan features"""
        self.module.params.update(
            {
                "scan_type": "syn",
                "ports": "22,80,443",
                "service_detection": True,
                "os_detection": True,
                "timing_template": 4,
                "host_discovery": "off",
                "scripts": ["ssl-enum-ciphers", "http-title"],
                "max_retries": 2,
                "min_rate": 100,
                "max_rate": 300,
            }
        )
        cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")

        # Verify all expected flags are present
        self.assertIn("-sS", cmd)  # SYN scan
        self.assertIn("-sV", cmd)  # Service detection
        self.assertIn("-O", cmd)  # OS detection
        self.assertIn("-T4", cmd)  # Timing template
        self.assertIn("-Pn", cmd)  # Skip host discovery
        self.assertIn("--script=ssl-enum-ciphers,http-title", cmd)  # Scripts
        self.assertIn("-p", cmd)  # Port specification flag
        self.assertIn("22,80,443", cmd)  # Ports to scan
        self.assertIn("--max-retries=2", cmd)  # Max retries
        self.assertIn("--min-rate=100", cmd)  # Min rate
        self.assertIn("--max-rate=300", cmd)  # Max rate

    def test_script_combinations(self):
        """Test different combinations of scripts"""
        script_combinations = [
            (["ssl-heartbleed"], "--script=ssl-heartbleed"),
            (["ssl-heartbleed", "vuln"], "--script=ssl-heartbleed,vuln"),
            (["default"], "--script=default"),
            (["auth", "vuln", "discovery"], "--script=auth,vuln,discovery"),
        ]

        for script_list, expected_script_arg in script_combinations:
            with self.subTest(script_list=script_list):
                self.module.params["scripts"] = script_list
                cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
                self.assertIn(expected_script_arg, cmd)

    def test_aggressive_scan_precedence(self):
        """Test that aggressive scan takes precedence over individual options"""
        self.module.params.update(
            {
                "aggressive_scan": True,
                "service_detection": True,
                "os_detection": True,
                "scan_type": "syn",
                "traceroute": True,  # Should be ignored if aggressive_scan is True
            }
        )
        cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")

        # Should only have aggressive flag, not individual options
        self.assertIn("-A", cmd)
        self.assertNotIn("-sV", cmd)
        self.assertNotIn("-O", cmd)
        self.assertNotIn("-sS", cmd)
        self.assertNotIn("--traceroute", cmd)

    def test_parsing_service_detection_output(self):
        """Test parsing output with service detection enabled"""
        output = self.get_sample_output_with_services()
        result = nmap.parse_nmap_output(output, service_detection=True)

        # Verify basic parsed info
        self.assertEqual(result["hosts_count"], 1)
        self.assertEqual(sorted(result["open_ports"]), [22, 80, 443])

        # Verify service info
        self.assertIn("scan_services", result)
        self.assertEqual(result["scan_services"]["22"], "ssh")
        self.assertEqual(result["scan_services"]["80"], "http")
        self.assertEqual(result["scan_services"]["443"], "https")

    def test_parsing_os_detection_output(self):
        """Test parsing output with OS detection enabled"""
        output = self.get_sample_output_with_os_info()
        result = nmap.parse_nmap_output(output, os_detection=True)

        # Verify OS detection info
        self.assertIn("os_matches", result)
        self.assertIn("Linux 5.4 - 5.5", result["os_matches"])

    @patch("library.nmap.AnsibleModule")
    @patch("library.nmap.get_nmap_path")
    def test_error_handling(self, mock_get_nmap_path, mock_ansible_module_class):
        """Test error handling when nmap command fails"""
        # Setup mock module with error return
        mock_module = MagicMock()
        mock_module.params = self.module.params
        mock_module.run_command.return_value = (1, "", "ERROR: nmap failed to execute")
        mock_module.get_bin_path.return_value = "/usr/bin/nmap"
        mock_ansible_module_class.return_value = mock_module

        # Skip actual nmap binary lookup
        mock_get_nmap_path.return_value = "/usr/bin/nmap"

        # Run the main function
        try:
            nmap.main()
        except SystemExit:
            pass  # Expected due to how ansible modules exit

        # Verify fail_json was called with the expected error message
        mock_module.fail_json.assert_called_once()
        args, kwargs = mock_module.fail_json.call_args
        self.assertEqual(kwargs["msg"], "Nmap scan failed")

    def test_dns_resolution_options(self):
        """Test DNS resolution options"""
        dns_options = [("always", "-n"), ("never", "--system-dns"), ("default", None)]

        for dns_resolution, expected_flag in dns_options:
            with self.subTest(dns_resolution=dns_resolution):
                self.module.params["dns_resolution"] = dns_resolution
                cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
                if expected_flag:
                    self.assertIn(expected_flag, cmd)
                else:
                    self.assertNotIn("-n", cmd)
                    self.assertNotIn("--system-dns", cmd)

    def test_interface_option(self):
        """Test interface specification"""
        # Test interface option with a specific interface
        self.module.params["interface"] = "eth0"
        cmd = nmap.build_nmap_command(self.module, "/usr/bin/nmap")
        self.assertIn("-e", cmd)
        self.assertIn("eth0", cmd)

    @patch("library.nmap.AnsibleModule")
    @patch("library.nmap.get_nmap_path")
    def test_json_output_handling(self, mock_get_nmap_path, mock_ansible_module_class):
        """Test handling of JSON output format"""
        # Set up parameters with JSON output
        params = dict(self.module.params)
        params.update(
            {
                "output_file": "/tmp/test_output.json",
                "output_format": "json",
            }
        )

        # Mock open and json.dump
        mock_module = MagicMock()
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.run_command.return_value = (0, self.get_sample_output(), "")
        mock_module.get_bin_path.return_value = "/usr/bin/nmap"

        # Skip actual nmap binary lookup
        mock_get_nmap_path.return_value = "/usr/bin/nmap"

        # Setup mock for AnsibleModule constructor
        mock_ansible_module_class.return_value = mock_module

        # Mock file operations to avoid file system changes
        with patch("builtins.open", mock_open()) as m_open, patch(
            "os.path.exists", return_value=True
        ) as mock_exists, patch("os.remove") as mock_remove, patch(
            "json.dump"
        ) as mock_json_dump:

            # Call the function directly with our controlled test environment
            from library.nmap import create_json_output

            # Mock parsed info that would come from parse_nmap_output
            parsed_info = {
                "hosts_count": 1,
                "open_ports": [22, 80, 443],
                "scan_services": {"22": "ssh", "80": "http", "443": "https"},
                "os_matches": ["Linux 5.4 - 5.5"],
            }

            # Call the function directly to avoid path resolution issues
            result = create_json_output(
                "/tmp/test_output.json", parsed_info, self.get_sample_output()
            )

            # Verify function returned success
            self.assertTrue(result)

            # Verify file operations were performed correctly
            m_open.assert_called_with("/tmp/test_output.json", "w")
            mock_json_dump.assert_called_once()

            # Test the full main function flow
            try:
                nmap.main()
            except SystemExit:
                pass  # Expected in Ansible modules

            # Verify the module exited successfully
            mock_module.exit_json.assert_called_once()

            # Verify the mocked file operations were used
            # XML file existence should be checked
            mock_exists.assert_called()
            # Check if the temporary XML file was removed
            mock_remove.assert_called()

    @patch("os.path.exists")
    @patch("os.remove")
    def test_json_output_cleanup(self, mock_remove, mock_exists):
        """Test cleanup of temporary XML files when creating JSON output"""
        # Set up module parameters with JSON output
        params = {
            "target": "localhost",
            "scan_type": "syn",
            "ports": "22",
            "output_file": "/tmp/output.json",
            "output_format": "json",
            "service_detection": True,
            "os_detection": True,
        }

        # Create a mock for AnsibleModule instance
        module = MagicMock()
        module.params = params
        module.check_mode = False

        # Mock successful command execution
        module.run_command.return_value = (
            0,
            "Nmap scan report for localhost",
            "",
        )
        module.get_bin_path.return_value = "/usr/bin/nmap"

        # Set up file exists mock to return True
        mock_exists.return_value = True

        # Patch json.dump and open to avoid actual file operations
        with patch("json.dump"), patch("builtins.open", mock_open()):
            # Run the code that should clean up the temp XML file
            result = nmap.main()
            # In a normal test we'd handle SystemExit here

        # Verify the cleanup happened
        mock_exists.assert_called_with("/tmp/output.json.xml")
        mock_remove.assert_called_with("/tmp/output.json.xml")

        # Check module function calls
        module.fail_json.assert_not_called()

        return result


class TestNmapRegressionAntipatterns(unittest.TestCase):
    """Examples of antipatterns in regression testing"""

    def test_antipattern_brittle_regression(self):
        """ANTIPATTERN: Brittle regression tests that break with minor changes"""
        # Creating a test that will break with even minor refactoring
        module = MagicMock()
        module.params = {"target": "localhost", "scan_type": "tcp", "ports": "22"}
        module.get_bin_path.return_value = "/usr/bin/nmap"

        # Using internal implementation details that could change
        # This test is intentionally an anti-pattern demonstration
        # Let's test the public API instead
        cmd = nmap.build_nmap_command(module, "/usr/bin/nmap")
        self.assertIn("-sT", cmd)

    def test_antipattern_testing_multiple_bugs_together(self):
        """ANTIPATTERN: Testing multiple bug fixes in a single test"""
        # This test is attempting to verify fixes for multiple unrelated bugs
        module = MagicMock()
        module.params = {
            "target": "localhost",
            "scan_type": "tcp",
            "ports": "22,23",
            "service_detection": True,
            "traceroute": True,
            "dns_resolution": "never",
        }

        cmd = nmap.build_nmap_command(module, "/usr/bin/nmap")

        # Testing three unrelated bug fixes in one test
        # Bug 1: Port parsing issue
        self.assertIn("22,23", cmd)
        # Bug 2: Service detection issue
        self.assertIn("-sV", cmd)
        # Bug 3: DNS resolution issue
        self.assertIn("--system-dns", cmd)

    def test_antipattern_fake_regression(self):
        """ANTIPATTERN: Regression test that doesn't actually test the regression"""
        # This test claims to test a regression but doesn't actually verify
        # the specific condition that caused the bug

        # Original bug: When scan_type was None, the module crashed
        module = MagicMock()
        module.params = {
            "target": "localhost",
            "scan_type": "tcp",  # Using a valid value instead of testing with None
            "ports": "22",
        }

        # This doesn't test the regression condition at all
        cmd = nmap.build_nmap_command(module, "/usr/bin/nmap")
        self.assertIn("-sT", cmd)

    def test_antipattern_redundant_regression(self):
        """ANTIPATTERN: Creating a regression test that duplicates a unit test"""
        # This test is essentially identical to a unit test, adding no value

        # This is a duplicate of test_build_nmap_command_with_service_detection
        module = MagicMock()
        module.params = {
            "target": "localhost",
            "scan_type": "tcp",
            "ports": "22",
            "service_detection": True,
        }

        cmd = nmap.build_nmap_command(module, "/usr/bin/nmap")
        self.assertIn("-sV", cmd)

    def test_antipattern_regression_without_comment(self):
        """ANTIPATTERN: Regression test without documenting the original issue"""
        # No comment explaining what bug this is testing
        module = MagicMock()
        module.params = {
            "target": "localhost",
            "scan_type": "tcp",
            "ports": "22,]",  # Malformed ports string
        }

        # This is actually testing a bug with malformed port strings
        # but there's no comment explaining the issue
        try:
            cmd = nmap.build_nmap_command(module, "/usr/bin/nmap")
            # If we reach here without exception, print the command that was built
            # and fail the test since we expected an exception
            self.fail(f"Expected ValueError was not raised. Command built was: {cmd}")
        except ValueError:
            pass  # Expected


if __name__ == "__main__":
    unittest.main()
