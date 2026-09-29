import unittest
from unittest.mock import MagicMock, patch

from panel.ssh_enrollment import install_over_ssh


class SshEnrollmentTests(unittest.TestCase):
    @patch("panel.ssh_enrollment._public_ip", return_value="203.0.113.42")
    @patch("panel.ssh_enrollment.paramiko.SSHClient")
    def test_installer_uses_supplied_password_and_closes_connection(self, ssh_client, _ip):
        client = ssh_client.return_value
        client.get_transport.return_value.get_remote_server_key.return_value.asbytes.return_value = b"host-key"
        stdout = MagicMock()
        stdout.channel.recv_exit_status.return_value = 0
        stdout.read.return_value = b"installed"
        stderr = MagicMock()
        stderr.read.return_value = b""
        client.exec_command.return_value = (None, stdout, stderr)

        result = install_over_ssh(
            host="203.0.113.42", port=22, username="root", password="one-time",
            command="printf ok | bash", timeout=30,
        )

        self.assertTrue(result["ok"])
        client.connect.assert_called_once_with(
            hostname="203.0.113.42", port=22, username="root", password="one-time",
            timeout=12, banner_timeout=12, auth_timeout=15,
            look_for_keys=False, allow_agent=False,
        )
        client.exec_command.assert_called_once_with("bash -lc 'printf ok | bash'", timeout=30)
        client.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
