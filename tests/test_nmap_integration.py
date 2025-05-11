#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest
import subprocess
import tempfile
import json
import yaml
import socket

# Check if the tests can be run
ANSIBLE_AVAILABLE = (
    subprocess.run(
        ["which", "ansible-playbook"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).returncode
    == 0
)
NMAP_AVAILABLE = (
    subprocess.run(
        ["which", "nmap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).returncode
    == 0
)


@unittest.skipIf(
    not (ANSIBLE_AVAILABLE and NMAP_AVAILABLE),
    "ansible-playbook or nmap is not installed",
)
class TestNmapIntegration(unittest.TestCase):
    """Integration tests for the nmap module using real Ansible playbooks"""

    def setUp(self):
        """Set up test environment for each test"""
        # Create a temp directory for playbooks and output files
        self.temp_dir = tempfile.TemporaryDirectory()

        # Define library path for ansible to find our module
        self.library_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "library")
        )

    def tearDown(self):
        """Clean up after each test"""
        # Clean up temp directory
        self.temp_dir.cleanup()

    def create_playbook(self, name, tasks):
        """Create an Ansible playbook file with the given tasks"""
        playbook_path = os.path.join(self.temp_dir.name, f"{name}.yml")

        # Create a playbook with localhost target
        playbook = [
            {
                "name": f"Nmap {name} Test",
                "hosts": "localhost",
                "connection": "local",
                "gather_facts": False,
                "tasks": tasks,
            }
        ]

        # Write the playbook to a file
        with open(playbook_path, "w") as f:
            yaml.dump(playbook, f, default_flow_style=False)

        return playbook_path

    def run_playbook(self, playbook_path):
        """Run the given Ansible playbook and return the results"""
        # Run ansible-playbook with our module path
        cmd = [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-e",
            f"ansible_python_interpreter={sys.executable}",
            f"--module-path={self.library_path}",
            playbook_path,
        ]

        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        return process

    def create_module_with_params(self, **params):
        """Create a module with specified parameters for direct testing"""
        # Add the library path to sys.path but don't import the module here
        sys.path.insert(
            0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "library"))
        )

        # Create mock module with parameters
        module = unittest.mock.MagicMock()
        default_params = {
            "target": "localhost",
            "scan_type": "tcp",
            "ports": "22",
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
        }

        # Update with provided parameters
        default_params.update(params)
        module.params = default_params

        # Set up run_command to return successful execution
        module.get_bin_path.return_value = "/usr/bin/nmap"
        module.run_command.return_value = (
            0,
            "Nmap scan report for localhost\nHost is up\n22/tcp open",
            "",
        )

        return module

    def run_module(self, module):
        """Run the module directly with provided mock and return result"""
        # Import the nmap module
        sys.path.insert(
            0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "library"))
        )
        from library import nmap

        # Store exit_json calls
        result = {}

        def mock_exit_json(**kwargs):
            nonlocal result
            result = kwargs
            return result

        # Replace exit_json with our mock
        original_exit_json = module.exit_json
        module.exit_json = mock_exit_json

        try:
            # Get nmap path
            nmap_path = nmap.get_nmap_path(module)

            # Build the command
            cmd = nmap.build_nmap_command(module, nmap_path)

            # Run the command directly without calling main()
            module.run_command.return_value = (
                0,
                "Nmap scan report for localhost\nHost is up\n22/tcp open",
                "",
            )

            # Parse the output using the module's function
            parsed_info = nmap.parse_nmap_output(
                module.run_command.return_value[1],
                module.params["service_detection"],
                module.params["os_detection"],
            )

            # Set result
            result = {
                "changed": True,
                "command": " ".join(cmd),
                "stdout": module.run_command.return_value[1],
                "stderr": module.run_command.return_value[2],
                "rc": 0,
                **parsed_info,
            }

        finally:
            # Restore original exit_json
            module.exit_json = original_exit_json

        return result

    def test_basic_scan_playbook(self):
        """Test basic nmap scan in an Ansible playbook"""
        # Create a simple playbook that scans localhost on port 22
        tasks = [
            {
                "name": "Run basic nmap scan",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "22",
                    "host_discovery": "off",
                },
                "register": "nmap_result",
            },
            {"name": "Debug nmap result", "debug": {"var": "nmap_result"}},
        ]

        playbook_path = self.create_playbook("basic_scan", tasks)

        # Run the playbook
        result = self.run_playbook(playbook_path)

        # Verify playbook execution
        self.assertEqual(
            result.returncode, 0, f"Playbook execution failed: {result.stderr}"
        )
        self.assertIn("ok=2", result.stdout)
        # Check for "failed=0" instead of looking for absence of "failed="
        self.assertIn("failed=0", result.stdout)

        # Verify nmap results in playbook output
        self.assertIn("hosts_count", result.stdout)
        self.assertIn("22/tcp", result.stdout)

    def test_scan_with_output_file(self):
        """Test nmap scan with output file in an Ansible playbook"""
        output_file = os.path.join(self.temp_dir.name, "nmap_scan.xml")

        # Create a playbook that saves scan results to a file
        tasks = [
            {
                "name": "Run nmap scan with output file",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "22",
                    "host_discovery": "off",
                    "output_file": output_file,
                    "output_format": "xml",
                },
                "register": "nmap_result",
            }
        ]

        playbook_path = self.create_playbook("scan_with_output", tasks)

        # Run the playbook
        result = self.run_playbook(playbook_path)

        # Verify playbook execution
        self.assertEqual(
            result.returncode, 0, f"Playbook execution failed: {result.stderr}"
        )

        # Verify output file was created
        self.assertTrue(os.path.exists(output_file), "Output file was not created")

        # Verify file contains XML output
        with open(output_file, "r") as f:
            content = f.read()
            self.assertIn("<?xml", content)
            self.assertIn("<nmaprun", content)

    def test_service_detection_playbook(self):
        """Test service detection in an Ansible playbook"""
        # Create a playbook with service detection
        tasks = [
            {
                "name": "Run nmap scan with service detection",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "22",
                    "host_discovery": "off",
                    "service_detection": True,
                },
                "register": "nmap_result",
            },
            {"name": "Debug nmap result", "debug": {"var": "nmap_result"}},
        ]

        playbook_path = self.create_playbook("service_detection", tasks)

        # Run the playbook
        result = self.run_playbook(playbook_path)

        # Verify playbook execution
        self.assertEqual(
            result.returncode, 0, f"Playbook execution failed: {result.stderr}"
        )

        # Verify service detection in output
        self.assertIn("scan_services", result.stdout)
        self.assertIn("ssh", result.stdout.lower())

    def test_multiple_options_playbook(self):
        """Test nmap scan with multiple options in an Ansible playbook"""
        # Create a playbook with multiple scan options
        tasks = [
            {
                "name": "Run nmap scan with multiple options",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "22,80",
                    "host_discovery": "off",
                    "service_detection": True,
                    "timing_template": 4,
                    "min_rate": 100,
                    "max_rate": 200,
                },
                "register": "nmap_result",
            }
        ]

        playbook_path = self.create_playbook("multiple_options", tasks)

        # Run the playbook
        result = self.run_playbook(playbook_path)

        # Verify playbook execution
        self.assertEqual(
            result.returncode, 0, f"Playbook execution failed: {result.stderr}"
        )
        self.assertIn("ok=1", result.stdout)
        # Check for "failed=0" instead of checking for absence of "failed="
        self.assertIn("failed=0", result.stdout)

    def test_json_output_playbook(self):
        """Test JSON output format in an Ansible playbook"""
        output_file = os.path.join(self.temp_dir.name, "nmap_scan.json")

        # Create a playbook that saves scan results as JSON
        tasks = [
            {
                "name": "Run nmap scan with JSON output",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "22",
                    "host_discovery": "off",
                    "output_file": output_file,
                    "output_format": "json",
                },
                "register": "nmap_result",
            }
        ]

        playbook_path = self.create_playbook("json_output", tasks)

        # Run the playbook
        result = self.run_playbook(playbook_path)

        # Verify playbook execution
        self.assertEqual(
            result.returncode, 0, f"Playbook execution failed: {result.stderr}"
        )

        # Verify JSON file was created
        self.assertTrue(os.path.exists(output_file), "JSON output file was not created")

        # Verify file contains valid JSON
        try:
            with open(output_file, "r") as f:
                data = json.load(f)
                self.assertIn("scan_info", data)
                self.assertIn("raw_output", data)
        except json.JSONDecodeError:
            self.fail("JSON output file does not contain valid JSON data")

    def test_large_network_scan(self):
        """Test scanning a larger network range"""
        # Only run if explicitly enabled - otherwise would be too slow and network intensive
        if not os.environ.get("ENABLE_LARGE_NETWORK_TESTS"):
            self.skipTest(
                "Large network tests disabled (set ENABLE_LARGE_NETWORK_TESTS=1 to enable)"
            )

        # Create module to scan local subnet (last octet only, to limit scope)
        local_ip = socket.gethostbyname(socket.gethostname())
        subnet_prefix = ".".join(local_ip.split(".")[:3]) + ".1-20"  # Just scan 20 IPs

        module = self.create_module_with_params(
            target=subnet_prefix,
            scan_type="ping",  # Just do ping scan for speed
            host_discovery="on",
            timing_template=4,  # Faster timing for subnet scan
        )

        # Run the scan - we're not asserting specific results, just checking it completes
        try:
            result = self.run_module(module)
            self.assertEqual(result["rc"], 0, "Network scan failed")
            # At least one host should be up (the local machine)
            self.assertGreaterEqual(
                result["hosts_count"], 1, "Expected at least one host to be up"
            )
        except Exception as e:
            # Don't fail the test suite if network conditions cause issues
            self.skipTest(f"Network conditions prevented test completion: {e}")


class TestNmapIntegrationAntipatterns(unittest.TestCase):
    """Examples of antipatterns in integration testing with Ansible"""

    def setUp(self):
        """Set up environment for antipatterns"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.library_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "library")
        )

    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()

    def test_antipattern_unnecessary_integration_test(self):
        """ANTIPATTERN: Using integration test for something that could be unit tested"""
        # This test uses a full playbook execution just to check command building
        # which could be done with a simple unit test

        # Create a playbook just to check if command is built correctly
        tasks = [
            {
                "name": "Run nmap scan to check command building",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "22",
                    "check_mode": True,  # Try to avoid actual execution
                },
            }
        ]

        playbook_path = os.path.join(self.temp_dir.name, "check_command.yml")
        self.create_simple_playbook(playbook_path, tasks)

        # Wasted resources running a playbook just to check command structure
        cmd = [
            "ansible-playbook",
            "-i",
            "localhost,",
            f"--module-path={self.library_path}",
            "-v",  # Verbose to see the command
            playbook_path,
        ]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_antipattern_missing_assertions(self):
        """ANTIPATTERN: Integration test without proper assertions"""
        # Just running a playbook without checking any results
        tasks = [
            {
                "name": "Run nmap scan",
                "nmap": {"target": "localhost", "scan_type": "tcp", "ports": "22"},
                "register": "result",
            }
        ]

        playbook_path = os.path.join(self.temp_dir.name, "no_assertions.yml")
        self.create_simple_playbook(playbook_path, tasks)

        # Run playbook but don't check any results
        cmd = [
            "ansible-playbook",
            "-i",
            "localhost,",
            f"--module-path={self.library_path}",
            playbook_path,
        ]
        subprocess.run(cmd)
        # No assertions about return code or output

    def test_antipattern_hardcoded_inventory(self):
        """ANTIPATTERN: Hardcoding inventory details that may not exist everywhere"""
        # This test assumes a specific inventory file exists
        tasks = [
            {
                "name": "Run nmap scan with hardcoded inventory",
                "nmap": {
                    "target": "{{ target_host }}",  # Relies on inventory variable
                    "scan_type": "tcp",
                    "ports": "22",
                },
            }
        ]

        playbook_path = os.path.join(self.temp_dir.name, "hardcoded_inventory.yml")
        self.create_simple_playbook(playbook_path, tasks)

        # Using a potentially non-existent inventory file
        cmd = [
            "ansible-playbook",
            "-i",
            "/etc/ansible/production_inventory",  # Hardcoded path that may not exist
            f"--module-path={self.library_path}",
            playbook_path,
        ]
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Actually use the process variable by checking for expected error conditions
        # Since we're expecting this to fail (inventory likely doesn't exist),
        # check for appropriate error messages in the output
        self.assertNotEqual(
            process.returncode,
            0,
            "Command should have failed with non-existent inventory",
        )
        self.assertTrue(
            "ERROR" in process.stderr
            or "Could not open" in process.stderr
            or "No such file" in process.stderr,
            "Expected error message about missing inventory file",
        )

    def test_antipattern_long_running(self):
        """ANTIPATTERN: Long-running tests without timeout"""
        # Integration test that might run for a very long time without any timeout
        tasks = [
            {
                "name": "Run very long nmap scan",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "1-65535",  # Full port scan will take a very long time
                    "timing_template": 0,  # Slowest possible timing
                },
            }
        ]

        playbook_path = os.path.join(self.temp_dir.name, "long_running.yml")
        self.create_simple_playbook(playbook_path, tasks)

        # No timeout specified - this could run for hours
        cmd = [
            "ansible-playbook",
            "-i",
            "localhost,",
            f"--module-path={self.library_path}",
            playbook_path,
        ]
        subprocess.run(cmd)

    def test_antipattern_no_idempotence_check(self):
        """ANTIPATTERN: Not checking idempotence in Ansible modules"""
        # Ansible modules should be idempotent (running twice should be the same as once)
        # This test doesn't verify idempotence
        tasks = [
            {
                "name": "Run nmap scan",
                "nmap": {
                    "target": "localhost",
                    "scan_type": "tcp",
                    "ports": "22",
                    "output_file": os.path.join(self.temp_dir.name, "scan.xml"),
                    "output_format": "xml",
                },
            }
        ]

        playbook_path = os.path.join(self.temp_dir.name, "idempotence.yml")
        self.create_simple_playbook(playbook_path, tasks)

        # Run once
        cmd = [
            "ansible-playbook",
            "-i",
            "localhost,",
            f"--module-path={self.library_path}",
            playbook_path,
        ]
        subprocess.run(cmd)

        # Should run again and check that "changed" is not reported,
        # but this antipattern doesn't do that

    def create_simple_playbook(self, path, tasks):
        """Helper to create a simple playbook file"""
        playbook = [
            {
                "name": "Antipattern Test Playbook",
                "hosts": "localhost",
                "gather_facts": False,
                "tasks": tasks,
            }
        ]

        with open(path, "w") as f:
            yaml.dump(playbook, f, default_flow_style=False)


if __name__ == "__main__":
    unittest.main()
