#!/usr/bin/python3
# coding: utf-8
# -*- coding: utf-8 -*-
#
#
#
# Date:        21.03.2022
# Version:     2.0.2
# Author V1:    Simon Jansen. GitHub: https://github.com/0x534a
# Author:      David Holin GitHub: https://github.com/SirGibihm
# Description:
# Script used to push files from to or fetch from a remote SFTP server
#

import argparse
import logging
import os
import paramiko
from paramiko import SFTPError
import psutil
import socket
import stat
import sys
import traceback

# Global variables
LOGGER = None


class SFTPyError(Exception):
    pass


class SFTPDirClient(paramiko.SFTPClient):

    def isdir(self, remote: str) -> bool:
        try:
            return stat.S_ISDIR(self.lstat(remote).st_mode)
        except IOError:
            return False

    def isfile(self, remote: str) -> bool:
        try:
            return stat.S_ISREG(self.lstat(remote).st_mode)
        except IOError:
            return False

    def exists(self, remote: str) -> bool:
        try:
            self.stat(remote)
            return True
        except IOError:
            return False

    def mkdir(self, path, mode=511, ignore_existing=False):
        "Allow for the directory to already exist without failing"
        try:
            super(SFTPDirClient, self).mkdir(path, mode)
        except IOError as e:
            if ignore_existing:
                pass
            else:
                raise

    def put_file(self, file_full_local_path: str, file_full_remote_path: str, overwrite: bool, delete: bool) -> int:

        if self.isfile(file_full_remote_path) == False or overwrite == True:
            self.put(file_full_local_path, file_full_remote_path)
            LOGGER.debug(
                f"Uploaded local file '{file_full_local_path}' to '{file_full_remote_path}'")
        else:
            LOGGER.debug(
                f"Skipped uploading local file '{file_full_local_path}' to '{file_full_remote_path} as it already exists")
            return 0

        if delete:
            os.remove(file_full_local_path)
            LOGGER.debug(
                f"Deleted local file '{file_full_local_path}' after upload")
        return 1

    def get_file(self, file_full_local_path: str, file_full_remote_path: str, overwrite: bool, delete: bool) -> int:
        if os.path.exists(file_full_local_path) == False or overwrite == True:
            self.get(file_full_remote_path, file_full_local_path)
            LOGGER.debug(
                f"Downloaded remote file '{file_full_remote_path}' to '{file_full_local_path}'")
        else:
            LOGGER.debug(
                f"Skipped downloading remote file '{file_full_remote_path}' to '{file_full_local_path} as it already exists")
            return 0

        if delete:
            self.remove(file_full_remote_path)
            LOGGER.debug(
                f"Deleted remote file '{file_full_remote_path}' after download")
        return 1

    def put_item(self, local: str, remote: str, overwrite: bool, delete: bool, uploaded_files=0) -> int:
        """
        """
        uploaded = uploaded_files
        item_name = os.path.basename(os.path.normpath(local))
        # TODO: Check if upload to windows SFTP breaks this
        item_full_remote_path = f"{remote}{item_name}" if remote.endswith(
            "/") else f"{remote}/{item_name}"

        # If it is a file, the remote dir exists on both source and remote at this point
        if os.path.isfile(local):
            if self.isdir(item_full_remote_path):
                LOGGER.critical(
                    f"The remote directory '{item_full_remote_path}' conflicts with upload of file '{local}'. Aborting.")
                raise SFTPyError
            uploaded = uploaded + \
                self.put_file(local, item_full_remote_path,
                              overwrite, delete)

        # If it is a directory
        elif os.path.isdir(local):

            if self.isfile(item_full_remote_path):
                LOGGER.critical(
                    f"The remote file '{item_full_remote_path}' conflicts with creation of directory '{local}'. Aborting.")
                raise SFTPyError
            self.mkdir(item_full_remote_path, ignore_existing=True)
            LOGGER.debug(f"Created remote directory '{item_full_remote_path}'")

            # Uploads the contents of the source directory to the remote path. The remote directory needs to exists. All subdirectories in source are created under target.
            for item in os.listdir(local):
                item_full_local_path = os.path.join(local, item)
                uploaded = uploaded + self.put_item(item_full_local_path, item_full_remote_path,
                                                    overwrite, delete, uploaded_files)

            if delete:
                os.rmdir(local)
                LOGGER.debug(f"Deleted local directory after upload '{local}'")

        else:
            LOGGER.warning(
                f"Item is neither dir nor file. Skipping: '{local}'")

        return uploaded

    def get_item(self, local: str, remote: str, overwrite: bool, delete: bool, downloaded_files=0) -> int:

        downloaded = downloaded_files
        item_name = os.path.basename(os.path.normpath(remote))
        item_full_local_path = os.path.join(local, item_name)

        # If it is a file, the remote dir exists on both remote and remote at this point
        if self.isfile(remote):
            if os.path.isdir(item_full_local_path):
                LOGGER.critical(
                    f"The local directory '{item_full_local_path}' conflicts with download file '{remote}'. Aborting.")
                raise SFTPyError
            downloaded = downloaded + \
                self.get_file(item_full_local_path, remote,
                              overwrite, delete)
            LOGGER.debug(
                f"Downloaded file '{remote}' to '{item_full_local_path}'")

        # If it is a directory
        elif self.isdir(remote):
            if os.path.isfile(item_full_local_path):
                LOGGER.critical(
                    f"The local file '{item_full_local_path}' conflicts with creation of directory '{remote}'. Aborting.")
                raise SFTPyError

            os.makedirs(item_full_local_path, exist_ok=True)
            LOGGER.debug(f"Created local directory '{item_full_local_path}'")

            for item in self.listdir(remote):
                item_full_remote_path = f"{remote}/{item}"
                downloaded = downloaded + \
                    self.get_item(item_full_local_path, item_full_remote_path,
                                  overwrite, delete, downloaded_files)
            if delete:
                self.rmdir(remote)
                LOGGER.debug(
                    f"Deleted remote directory after download '{remote}'")

        else:
            LOGGER.error(
                f"Tried to download something that is neither directory nor file: '{remote}', skipping.")

        return downloaded


class SSHClientSFTP(paramiko.SSHClient):
    pass


def handle_parameters():
    """ Handles the script parameters
    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Script to robustly up- and download data from and to SFTP shares")

    # General script parameters
    method = parser.add_mutually_exclusive_group(required=True)
    method.add_argument("--put",
                        help="Put file or directory to server",
                        action='store_true',
                        default=False)
    method.add_argument("--get",
                        help="Fetch file or directory from server",
                        action='store_true',
                        default=False)
    parser.add_argument("-s", "--server",
                        help="SFTP server IP",
                        required=True)
    parser.add_argument("-p", "--port",
                        help="SFTP server port",
                        type=int,
                        default=22)
    parser.add_argument("-u", "--user",
                        help="SFTP user",
                        required=True)
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--pw",
                            help="Password for SFTP user password")
    auth_group.add_argument("-i", "--identity",
                            help="Identity file for SFTP user (SSH private key)")
    parser.add_argument("-l", "--local",
                        help="Local Directory where stuff is put, defaults (Default: ./)",
                        default="./")
    parser.add_argument("-r", "--remote", help="Destination on where to put files (Default: ./)",
                        default="./")
    parser.add_argument("--jump-server", help="Jump Server")
    parser.add_argument("--jump-server-port",
                        help="Jump Server", type=int, default=22)
    parser.add_argument(
        "-k", "--lock", help="Lock file, no lock collision is observed if not given.")
    parser.add_argument("-g", "--log-file",
                        help="Log file, logs to console if no file is given (Default)",)
    parser.add_argument("--log-level", help="Log Level (Default INFO)",
                        choices=["DEBUG", "INFO",
                                 "WARNING", "ERROR", "CRITICAL"],
                        default="INFO")
    parser.add_argument("-w", "--overwrite",
                        help="Overwrite files at destination if they allready exist",
                        action='store_true',
                        default=False)
    parser.add_argument("-d", "--delete",
                        help="Delete files from local directory after pushing",
                        action='store_true',
                        default=False)
    #parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))
    args = parser.parse_args()
    return args


def set_up_logging(log_file: str, log_level: str) -> logging.Logger:
    """
    Sets up the logging infrastructure
    """
    root_logger = logging.getLogger()

    if log_file:
        handler = logging.FileHandler(log_file, mode="a+", encoding="utf8")
    else:
        handler = logging.StreamHandler()

    log_formatter = logging.Formatter(
        "[%(asctime)s] [%(process)d] [%(levelname)s]: %(message)s")
    handler.setFormatter(log_formatter)

    if log_level == "DEBUG":
        root_logger.setLevel(logging.DEBUG)
    elif log_level == "INFO":
        root_logger.setLevel(logging.INFO)
    elif log_level == "WARNING":
        root_logger.setLevel(logging.WARNING)
    elif log_level == "ERROR":
        root_logger.setLevel(logging.ERROR)
    elif log_level == "CRITICAL":
        root_logger.setLevel(logging.CRITICAL)

    root_logger.addHandler(handler)
    if log_file:
        root_logger.debug("Logging into LogFile : '{log_file}'")
    else:
        root_logger.debug("Logging into stdout enabled.")
    return root_logger


def process_lock(lockfile: str):

    myPID = os.getpid()
    if os.path.isfile(lockfile):

        with open(lockfile, "r") as f:
            content = f.read()
            try:
                pid = int(content)
                if psutil.pid_exists(pid):
                    if psutil.Process(pid).name() == "sftp_push.py":
                        LOGGER.warning(
                            "Script instance is already running. Aborting.")
                        sys.exit(0)
            except ValueError:
                LOGGER.warning(
                    f"Invalid contents were written to lockfile located at: {lockfile}")
            LOGGER.warning(
                f"Deleting stale lockfie located at: {lockfile}")
        os.remove(lockfile)

    # Create lock file and write own PID into it
    with open(lockfile, "w+") as f:
        f.write(str(myPID))
        f.close()


def establish_connection(ssh_client: paramiko.SSHClient, server: str, user: str, password: str, key_file: str,  port: int = 22,  channel=None):
    try:
        if password:
            if channel:
                ssh_client.connect(
                    server, port=port, username=user, password=password, sock=channel)
            else:
                ssh_client.connect(server, port=port,
                                   username=user, password=password)
        elif key_file:
            if channel:
                ssh_client.connect(
                    server, port=port, username=user, key_filename=key_file, sock=channel)
            else:
                ssh_client.connect(server, port=port,
                                   username=user, key_filename=key_file)
        else:
            LOGGER.critical(
                f"Neither password nor identity file given. Aborting.")
            raise SFTPError

    except paramiko.ssh_exception.SSHException as err:
        LOGGER.critical(
            f"SSH Key of '{server}' not found in known hosts. Aborting.")
        raise SFTPyError
    except paramiko.ssh_exception.NoValidConnectionsError as err:
        LOGGER.critical(
            f"Unable to connect to port '{port}' of server '{server}'. Aborting.")
        raise SFTPyError
    except TimeoutError as err:
        LOGGER.critical(
            f"Communication attempt to '{server}' timed out. Aborting.")
        raise SFTPyError


def set_up_sftp(server: str, port: int, user: str, pw: str, identity_file: str, jump_server: str = None, jump_server_port: int = 22):
    # Negotiate SSH2 connection between server and client
    try:

        # Start SFTP server
        target = paramiko.SSHClient()
        target.load_system_host_keys()

        jumpbox_channel = None
        # Start jumpserver if given
        if jump_server:
            jumpbox = paramiko.SSHClient()
            jumpbox.load_system_host_keys()
            establish_connection(ssh_client=jumpbox, user=user, password=pw,
                                 key_file=identity_file, server=jump_server, port=jump_server_port)
            jumpbox_transport = jumpbox.get_transport()
            jumpbox_channel = jumpbox_transport.open_channel(
                "direct-tcpip", (server, port), (jump_server, jump_server_port))

        establish_connection(ssh_client=target, server=server, user=user, password=pw,
                             key_file=identity_file, channel=jumpbox_channel, port=port)
        sftp_session = SFTPDirClient.from_transport(target.get_transport())

        # Paramiko logs the success of this operation as "INFO" but without any information about the connection
        if jump_server:
            LOGGER.debug(
                f"User '{user}' connected to SFTP server '{server}:{port}' using proxy '{jump_server}'")
        else:
            LOGGER.debug(
                f"User '{user}' connected to SFTP server '{server}:{port}'")
        return sftp_session

    except socket.gaierror as ex:
        # raise ex
        LOGGER.critical(f"Invalid SFTP server: '{server}'. Aborting.")
        raise SFTPyError


def main():
    """
    Main entry point of the script
    """
    global LOGGER
    lock_created = False
    try:
        # Argument handling
        args = handle_parameters()

        # Initialize logging
        set_up_logging(args.log_file, args.log_level)
        LOGGER = logging.getLogger()

        # check if a lock file exists
        if args.lock:
            process_lock(args.lock)
            lock_created = True
            LOGGER.info("Lockfile created at:'{}'".format(args.lock))

        # Prepare Identify File
        if args.identity:
            if not os.path.isfile(args.identity):
                LOGGER.critical(
                    f"Identity file at '{args.identity}' could not be found. Aborting.")
                raise SFTPyError
            else:
                LOGGER.debug(f"Identity file found at '{args.identity}'")

        files_moved = 0
        # Start SFTP connection
        sftp_session = set_up_sftp(args.server, args.port, args.user,
                                   args.pw, args.identity, args.jump_server, args.jump_server_port)

        # Upload file or directory to remote sftp location
        if args.put:
            if not sftp_session.isdir(args.remote):
                LOGGER.critical(
                    f"Remote target directory does not exist: '{args.remote}'. Aborting.")
                raise SFTPyError
            if not os.path.exists(args.local):
                LOGGER.critical(
                    f"Local source directory or file does not exist: '{args.local}'. Aborting.")
                raise SFTPyError
            files_moved = sftp_session.put_item(
                args.local, args.remote, args.overwrite, args.delete)

        # Download file or directory from remote sftp location
        elif args.get:
            if not sftp_session.exists(args.remote):
                LOGGER.critical(
                    f"Remote source file or directory does not exist: '{args.remote}'. Aborting.")
                raise SFTPyError

            if not os.path.isdir(args.local):
                LOGGER.critical(
                    f"Local target directory does not exist: '{args.local}'. Aborting.")
                raise SFTPyError

            files_moved = sftp_session.get_item(
                args.local, args.remote, args.overwrite, args.delete)
        LOGGER.info(f"Transfered a total of {files_moved} files")
        if args.delete:
            LOGGER.info("Source-data was deleted after up-/download.")

        # Disconnect
        try:
            sftp_session.close()
        except Exception as e:
            LOGGER.error(
                "Failed to close connection to SFTP server due to unknown reason")

    # These kinds of Errors are allready known and handled accordingly. A logging message was already thrwon.
    except SFTPyError as ex:
        pass
    except Exception as ex:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        st = traceback.format_exception(
            exc_type, exc_value, exc_traceback, limit=8)
        LOGGER.critical(
            f"A fatal error occurred. Error message was: {ex} (stack trace: {st}). Aborting.")
        sys.exit(1)

    finally:
        if lock_created:
            # Remove lock file
            if os.path.isfile(args.lock):
                os.remove(args.lock)
                LOGGER.info(
                    "sftp_pypeline.py has finished. lock File was removed.")
            else:
                LOGGER.warning(
                    f"sftp_pypeline.py has finished. No lock file was found at '{args.lock}', no clean up was conducted.")


if __name__ == '__main__':
    main()
