import hashlib
import os

from netmiko import ConnectHandler
from scp import SCPClient, SCPException


class FileTransferError(Exception):
    pass


class FileCopy(object):
    def __init__(self, driver, source_file, dest_file=None, direction='put', file_system=None):
        if direction not in ["put", "get"]:
            raise ValueError("Invalid direction {}".format(direction))

        self.driver = driver
        self.source_file = source_file
        self.dest_file = dest_file or os.path.basename(source_file)
        self.direction = direction
        self.file_system = file_system
        self._ssh = ConnectHandler(device_type='cisco_ios', ip=driver.hostname,
                                   username=driver.username, password=driver.password)
        self._ssh.enable()

    def __enter__(self):
        self._connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._disconnect()

    def get_file(self):
        self._transfer_wrapper("get")

    def put_file(self):
        self._transfer_wrapper("put")

    def _transfer_wrapper(self, direction):
        if self.direction != direction:
            raise FileTransferError("Direction/method mismatch")
        if not self._compare_md5():
            self._verify_space_and_transfer()

        if not self._compare_md5():
            raise FileTransferError("File transferred, but md5 does not match")

    def _verify_space_and_transfer(self):
        if not self._verify_space_available():
            raise FileTransferError("Insufficient space available on device")
        try:
            with SCPClient(self._ssh.remote_conn.get_transport()) as s:
                getattr(s, self.direction)(self.source_file, self.dest_file)
        except SCPException as e:
            raise FileTransferError("Error transferring file: {}".format(e))

    def _connect(self):
        if not self._ssh.remote_conn.get_transport().is_active():
            self._ssh.establish_connection()
            self._ssh.enable()

    def _disconnect(self):
        if self._ssh.remote_conn.get_transport().is_active():
            self._ssh.disconnect()

    def _local_file_size(self):
        return os.stat(self.source_file).st_size

    def _remote_file_size(self):
        return int(self._ssh.send_command("bash wc -c < {}".format(self.source_file)))

    def _local_file_md5(self):
        if self.direction == "put":
            fname = self.source_file
        else:
            fname = self.dest_file
        if os.path.isfile(fname):
            m = hashlib.md5()
            with open(fname, "rb") as f:
                buf = f.read(2**20)
                while buf:
                    m.update(buf)
                    buf = f.read(2**20)
            return m.hexdigest()

    def _remote_file_md5(self):
        if self.direction == "put":
            fname = self.dest_file
        else:
            fname = self.source_file
        return self._ssh.send_command("bash /usr/bin/md5sum {}".format(fname)).split()[0]

    def _compare_md5(self):
        return self._local_file_md5() == self._remote_file_md5()

    def _local_space_available(self):
        ret = os.statvfs(os.path.dirname(self.dest_file))
        return ret.f_bsize * ret.f_bavail

    def _remote_space_available(self):
        path = os.path.dirname(self.dest_file)
        if path == '':
            path = '.'
        return int(self._ssh.send_command("bash df -B1 {}".format(path)).splitlines()[1].split()[3])

    def _verify_space_available(self):
        if self.direction == "put":
            return self._local_file_size() < self._remote_space_available()
        else:
            return self._remote_file_size() < self._local_space_available()
