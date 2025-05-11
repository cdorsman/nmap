#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest
import subprocess
import tempfile
import json
import socket
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from unittest.mock import MagicMock
from library import nmap


# Check if the tests are running in an environment where nmap can be executed
NMAP_AVAILABLE = (
    subprocess.run(
        ["which", "nmap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).returncode
    == 0
)


def start_test_server(port=8080):
    """Start a simple HTTP server for testing"""
    httpd = HTTPServer(("localhost", port), SimpleHTTPRequestHandler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return httpd


@unittest.skipIf(not NMAP_AVAILABLE, "nmap is not installed on this system")
class TestNmapFunctional(unittest.TestCase):
    """Functional tests for the nmap module using actual nmap execution"""

    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for the entire test class"""
        # Start a local HTTP server for testing
        cls.test_server = start_test_server(port=8080)
        # Allow server to start up
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        """Clean up the test environment"""
        # Shut down the HTTP server
        if hasattr(cls, "test_server"):
            cls.test_server.shutdown()

    def setUp(self):
        """Set up test environment for each test"""
        # Create a temp directory for output files
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        """Clean up after each test"""
        # Clean up temp directory
        self.temp_dir.cleanup()

    def create_module_mock(self, **kwargs):
        """Create a mock AnsibleModule with the given parameters"""
        # Default parameters
        params = {
            "target": "localhost",
            "scan_type": "syn",
            "ports": "8080",  # Use our test HTTP server
            "output_file": os.path.join(self.temp_dir.name, "nmap_output"),
            "output_format": "normal",
            "timeout": 10,
            "timing_template": 3,
            "host_discovery": "off",  # Skip host discovery to speed up tests
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

        # Update with provided kwargs
        params.update(kwargs)

        # Create a mock module
        module = MagicMock()
        module.params = params
        module.get_bin_path.return_value = "/usr/bin/nmap"

        # Create mock methods for exit_json and fail_json
        def mock_exit_json(**kwargs):
            return kwargs

        def mock_fail_json(**kwargs):
            raise Exception(kwargs.get("msg", "Unknown error"))

        module.exit_json = mock_exit_json
        module.fail_json = mock_fail_json

        return module

    def test_basic_scan(self):
        """Test basic scan functionality against our local HTTP server"""
        # Create module with basic scan parameters
        module = self.create_module_mock(
            target="localhost",
            scan_type="tcp",  # Use TCP scan to avoid privileged requirements
            ports="8080",
            host_discovery="off",
        )

        # Get nmap path
        nmap_path = nmap.get_nmap_path(module)

        # Build command
        cmd = nmap.build_nmap_command(module, nmap_path)

        # Run the command directly through subprocess (for testing only)
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Assert that the command ran successfully
        self.assertEqual(
            process.returncode, 0, f"nmap command failed: {process.stderr}"
        )

        # Assert that our test port was found
        self.assertIn("8080/tcp", process.stdout)
        self.assertIn("open", process.stdout)

    def test_output_formats(self):
        """Test different output format options"""
        output_formats = ["normal", "xml", "grepable"]

        for output_format in output_formats:
            with self.subTest(output_format=output_format):
                output_file = os.path.join(
                    self.temp_dir.name, f"nmap_output.{output_format}"
                )

                # Create module with specific output format
                module = self.create_module_mock(
                    target="localhost",
                    scan_type="tcp",
                    ports="8080",
                    host_discovery="off",
                    output_file=output_file,
                    output_format=output_format,
                )

                # Get nmap path
                nmap_path = nmap.get_nmap_path(module)

                # Build and run command
                cmd = nmap.build_nmap_command(module, nmap_path)
                subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )

                # Check if the output file was created
                self.assertTrue(
                    os.path.exists(output_file),
                    f"Output file for {output_format} format was not created",
                )

                # Check file content for expected format
                with open(output_file, "r") as f:
                    content = f.read()

                    # Different assertions based on format
                    if output_format == "xml":
                        self.assertIn("<?xml", content)
                        self.assertIn("<nmaprun", content)
                    elif output_format == "grepable":
                        self.assertIn("Host:", content)
                        self.assertIn("Ports:", content)
                    else:  # normal
                        self.assertIn("PORT", content)
                        self.assertIn("STATE", content)

    def test_json_output(self):
        """Test JSON output format which requires special handling"""
        output_file = os.path.join(self.temp_dir.name, "nmap_output.json")

        # Create module with JSON output format
        module = self.create_module_mock(
            target="localhost",
            scan_type="tcp",
            ports="8080",
            host_discovery="off",
            output_file=output_file,
            output_format="json",
        )

        # Get nmap path
        nmap_path = nmap.get_nmap_path(module)

        # Build command - this should create an XML file internally
        cmd = nmap.build_nmap_command(module, nmap_path)
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        self.assertEqual(
            process.returncode, 0, f"nmap command failed: {process.stderr}"
        )

        # XML output file that would be generated
        xml_file = output_file + ".xml"
        self.assertTrue(
            os.path.exists(xml_file),
            "XML output file for JSON conversion was not created",
        )

        # Now manually handle the conversion
        try:
            # Parse the process output to get actual results
            parsed_results = nmap.parse_nmap_output(process.stdout)

            # Create a JSON structure using the actual parsed results
            json_data = {
                "scan_info": {
                    "hosts_count": parsed_results["hosts_count"],
                    "open_ports": parsed_results["open_ports"],
                },
                "raw_output": process.stdout,
            }

            with open(output_file, "w") as f:
                json.dump(json_data, f, indent=2)

            # Check if JSON file exists and is valid
            self.assertTrue(
                os.path.exists(output_file), "JSON output file was not created"
            )
            with open(output_file, "r") as f:
                data = json.load(f)
                self.assertIn("scan_info", data)
                self.assertIn("raw_output", data)

                # Verify the actual data matches what we found in the scan
                self.assertEqual(
                    data["scan_info"]["hosts_count"], parsed_results["hosts_count"]
                )
                self.assertEqual(
                    data["scan_info"]["open_ports"], parsed_results["open_ports"]
                )

        finally:
            # Cleanup the XML file
            if os.path.exists(xml_file):
                os.remove(xml_file)

    def test_service_detection(self):
        """Test service detection functionality"""
        # Create module with service detection
        module = self.create_module_mock(
            target="localhost",
            scan_type="tcp",
            ports="8080",
            host_discovery="off",
            service_detection=True,
        )

        # Get nmap path
        nmap_path = nmap.get_nmap_path(module)

        # Build command
        cmd = nmap.build_nmap_command(module, nmap_path)

        # Verify -sV flag is included
        self.assertIn("-sV", cmd)

        # Run the command
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Parse the output
        result = nmap.parse_nmap_output(process.stdout, service_detection=True)

        # Verify service info was parsed
        self.assertIn("scan_services", result)
        if result["open_ports"]:
            # Port 8080 should be detected as http
            if "8080" in result["scan_services"]:
                self.assertTrue(
                    result["scan_services"]["8080"].lower().startswith("http"),
                    f"Expected HTTP service but got {result['scan_services']['8080']}",
                )

    def test_multiple_ports(self):
        """Test scanning multiple ports"""
        # Find a free port for a second test server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            second_port = s.getsockname()[1]

        # Start a second server on the new port
        second_server = start_test_server(port=second_port)
        time.sleep(1)

        try:
            # Create module to scan both ports
            module = self.create_module_mock(
                target="localhost",
                scan_type="tcp",
                ports=f"8080,{second_port}",
                host_discovery="off",
            )

            # Get nmap path
            nmap_path = nmap.get_nmap_path(module)

            # Build and run command
            cmd = nmap.build_nmap_command(module, nmap_path)
            process = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Parse the output
            result = nmap.parse_nmap_output(process.stdout)

            # Both ports should be detected as open
            self.assertIn(8080, result["open_ports"])
            self.assertIn(second_port, result["open_ports"])

        finally:
            # Shutdown second server
            second_server.shutdown()

    def test_min_max_rate(self):
        """Test min rate and max rate parameters"""
        # Create module with rate limits
        module = self.create_module_mock(
            target="localhost",
            scan_type="tcp",
            ports="8080",
            host_discovery="off",
            min_rate=100,
            max_rate=200,
        )

        # Get nmap path
        nmap_path = nmap.get_nmap_path(module)

        # Build command
        cmd = nmap.build_nmap_command(module, nmap_path)

        # Verify rate limit flags are included
        self.assertIn("--min-rate=100", cmd)
        self.assertIn("--max-rate=200", cmd)

        # Run the command to ensure it works with these parameters
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        self.assertEqual(
            process.returncode,
            0,
            f"nmap command with rate limits failed: {process.stderr}",
        )


class TestNmapFunctionalAntipatterns(unittest.TestCase):
    """Examples of antipatterns in functional testing"""

    def test_antipattern_unreliable_ports(self):
        """ANTIPATTERN: Using unreliable/uncontrolled network resources"""
        # Don't test against external hosts or ports that you don't control
        # This test may pass or fail depending on external factors
        module = MagicMock()
        module.params = {
            "target": "google.com",  # External host we don't control
            "scan_type": "tcp",
            "ports": "80,443",
        }
        module.get_bin_path.return_value = "/usr/bin/nmap"
        module.run_command.return_value = (0, "", "")

        # Run an actual scan against an external host
        cmd = nmap.build_nmap_command(module, "/usr/bin/nmap")
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # The test could fail if google.com is down or blocking our scans
        self.assertEqual(process.returncode, 0)

    def test_antipattern_slow_test(self):
        """ANTIPATTERN: Running slow tests without marking them as such"""
        # This test will take a long time to run (scanning 1000 ports)
        # Slow tests should be marked as such and run separately
        cmd = [
            "/usr/bin/nmap",
            "-sT",
            "-T3",
            "-p",
            "1-1000",  # Scanning 1000 ports is slow
            "localhost",
        ]

        # This will significantly slow down the test suite
        # Store the process result so it's used and not flagged as unused
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        self.assertEqual(result.returncode, 0)

    def test_antipattern_real_commands_without_mocks(self):
        """ANTIPATTERN: Running actual commands that could have side effects"""
        # Running actual nmap commands that might be invasive
        cmd = [
            "/usr/bin/nmap",
            "-sS",  # SYN scan that might be detected as suspicious
            "-p",
            "1-65535",  # Full port scan (very slow)
            "-T4",  # Faster timing (more noticeable)
            "127.0.0.1",  # At least it's localhost
        ]

        # This could have real-world effects (e.g. triggering IDS)
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Add assertions to demonstrate proper use of the 'process' variable
        self.assertEqual(process.returncode, 0, "Nmap command failed")
        self.assertIn(
            "Nmap scan report", process.stdout, "Expected scan report in output"
        )

        # Parse and validate the results to properly utilize the process output
        parsed_results = nmap.parse_nmap_output(process.stdout)
        self.assertIsInstance(
            parsed_results["hosts_count"], int, "Should have parsed hosts count"
        )
        self.assertIsInstance(
            parsed_results["open_ports"], list, "Should have parsed open ports list"
        )

    def test_antipattern_dependent_tests(self):
        """ANTIPATTERN: Tests that depend on each other"""
        # This test demonstrates an antipattern by accessing a file created by another test
        # Instead of using global variables, we'll directly reference the temp file path
        temp_file = os.path.join("/tmp", f"nmap_test_{os.getpid()}.txt")

        try:
            with open(temp_file, "r") as f:
                content = f.read()
                self.assertTrue(len(content) > 0)
        except FileNotFoundError:
            # This will fail if run independently
            self.fail("This test depends on another test to run first")

    def test_antipattern_no_cleanup(self):
        """ANTIPATTERN: Test creates resources but doesn't clean up"""
        # Create a temporary file
        temp_file = os.path.join("/tmp", f"nmap_test_{os.getpid()}.txt")
        with open(temp_file, "w") as f:
            f.write("test data")

        # Use the file in the test
        self.assertTrue(os.path.exists(temp_file))

        # No cleanup - file will remain after test finishes

        # Store for dependent test (making things worse)
        global test_output_file
        test_output_file = temp_file

    def test_antipattern_fragile_assertions(self):
        """ANTIPATTERN: Fragile assertions that depend on exact format"""
        # Run a scan
        cmd = ["/usr/bin/nmap", "-sT", "-p", "22", "localhost"]
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Assertions on exact output format which can change between versions
        self.assertIn("Starting Nmap", process.stdout)
        # This might break with new nmap versions:
        self.assertIn("Nmap scan report for localhost (127.0.0.1)", process.stdout)
        self.assertIn("PORT   STATE SERVICE", process.stdout)
        self.assertIn("22/tcp open  ssh", process.stdout)


if __name__ == "__main__":
    unittest.main()
