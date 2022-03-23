#!/usr/bin/python3
# coding: utf-8
# -*- coding: utf-8 -*-
#
#
#
# Date:        21.03.2022
# Version:     2.0
# Author V1    Simon Jansen. GitHub: https://github.com/0x534a
# Author:      David Holin GitHub: https://github.com/SirGibihm
# Description:
#  Script used to push files from to or fetch from a remote SFTP server
#

import sys
import traceback
import logging
import argparse
import os
import socket
import paramiko
import psutil
import stat


__version__ = "2.0"

# Global variables
LOGGER = None

class SFTPDirClient(paramiko.SFTPClient):
     
    def dirExists(self, remote:str):
        try:
            stat.S_ISDIR(self.lstat(remote).st_mode)
            return True
        except IOError:
            return False

    def exists(self, remote:str):
        try:
            self.stat(remote)
            return True
        except IOError:
            return False

    def mkdir(self, path, mode=511, ignore_existing=False):
        """ Augments mkdir by adding an option to not fail if the folder exists
        """
        try:
            super(SFTPDirClient, self).mkdir(path, mode)
        except IOError:
            if ignore_existing:
                pass
            else:
                raise

    def is_file(self, target_path: str):
        try:
            self.stat(target_path)
            return True
        except IOError:
            return False

    def put_file(self, file_full_local_path: str, file_full_remote_path:str, overwrite:bool, delete:bool):

        if self.is_file(file_full_remote_path) == False or overwrite == True:
            self.put(file_full_local_path, file_full_remote_path)
            LOGGER.info(f"Uploaded local file '{file_full_local_path}' to '{file_full_remote_path}'")
        else:
            LOGGER.info(f"Skipped uploading local file '{file_full_local_path}' to '{file_full_remote_path} as it already exists")
            return 0

        if delete:
            os.remove(file_full_local_path)
            LOGGER.info("Deleted local file '{file_full_remote_path}' after pushing")
        return 1

    def get_file(self, file_full_local_path, file_full_remote_path, overwrite, delete):

        if os.path.exists(file_full_local_path) == False or overwrite == True:
            self.get(file_full_remote_path, file_full_local_path)
            LOGGER.info(f"Downloaded remote file '{file_full_remote_path}' to '{file_full_local_path}'")
        else:
            LOGGER.info(f"Skipped downloading remote file '{file_full_remote_path}' to '{file_full_local_path} as it already exists")
            return 0

        if delete:
            self.remove(file_full_remote_path)
            LOGGER.info(f"Deleted remote file '{file_full_remote_path}' after pushing")

        return 1

    def put_item(self, local: str, remote: str, overwrite: bool, delete_after_upload: bool, uploaded_files=0):

        uploaded = uploaded_files
        item_name = os.path.basename(os.path.normpath(local))
        # TODO: Check if upload to windows SFTP breaks this
        item_full_remote_path = f"{remote}/{item_name}"

        # If it is a file, the remote dir exists on both source and remote at this point
        if os.path.isfile(local):
            uploaded = uploaded + \
                self.put_file(local, item_full_remote_path,
                              overwrite, delete_after_upload)

        # If it is a directory
        elif os.path.isdir(local):

            self.mkdir(item_full_remote_path, ignore_existing=True)
            LOGGER.debug(f"Created remote directory '{item_full_remote_path}'")

            # Uploads the contents of the source directory to the remote path. The remote directory needs to exists. All subdirectories in source are created under target.
            for item in os.listdir(local):
                item_full_local_path = os.path.join(local, item)
                uploaded = uploaded + self.put_item(item_full_local_path, item_full_remote_path,
                                  overwrite, delete_after_upload, uploaded_files)

        else:
            LOGGER.warning(f"Item is neither dir nor file. Skipping: '{local}'")

        return uploaded

    def get_item(self, local: str, remote: str, overwrite: bool, delete_after_upload: bool, downloaded_files=0):

        downloaded = downloaded_files
        item_name = os.path.basename(os.path.normpath(remote))
        item_full_local_path = os.path.join(local, item_name)

        # If it is a file, the remote dir exists on both remote and remote at this point
        if stat.S_ISREG(self.lstat(remote).st_mode):
            downloaded = downloaded + \
                self.get_file(item_full_local_path, remote,
                              overwrite, delete_after_upload)
            LOGGER.debug(
                f"Downloaded file '{remote}' to '{item_full_local_path}'")

        # If it is a directory
        elif stat.S_ISDIR(self.lstat(remote).st_mode):
            if not os.path.exists(item_full_local_path):
                os.makedirs(item_full_local_path)
            LOGGER.debug(f"Created local directory '{item_full_local_path}'")
                

            for item in self.listdir(remote):
                item_full_remote_path = "{}/{}".format(remote, item)
                downloaded = downloaded + \
                    self.get_item(item_full_local_path, item_full_remote_path,
                                  overwrite, delete_after_upload, downloaded_files)

        else:
            raise Exception(
                "Tried to download something unknown: '{}'".format(remote))

        return downloaded


def handle_parameters():
    """ Handles the script parameters
    :param argv: Script arguments
    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Script used to create a OpenVPN user configuration file")

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
    parser.add_argument("--proxy", help="Proxy SSH server")
    parser.add_argument("-k", "--lock", help="Lock file, no lock collision is observed if not given.")
    parser.add_argument("-g", "--log-file",
                        help="Log file, logs to console if no file is given (Default)",)
    parser.add_argument("--log-level", help="Log Level (Default INFO)",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO")
    parser.add_argument("-w", "--overwrite",
                        help="Overwrite files at destination if they allready exist",
                        action='store_true',
                        default=False)
    parser.add_argument("-d", "--delete",
                        help="Delete files from local directory after pushing",
                        action='store_true',
                        default=False)
    args = parser.parse_args()
    return args


def set_up_logging(log_file: str, log_level: str):
    """
    Sets up the logging infrastructure
    """
    root_logger = logging.getLogger()

    if log_file:
        handler = logging.FileHandler(log_file, mode="a+", encoding="utf8")
    else:
        handler = logging.StreamHandler()
    
    log_formatter = logging.Formatter("[%(asctime)s] [%(process)d] [%(levelname)s]: %(message)s")
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


def process_lock(lockfile: str):

    myPID = os.getpid()
    if os.path.isfile(lockfile):

        with open(lockfile, "r") as f:
            content = f.read()
            try:
                pid = int(content)
                if psutil.pid_exists(pid):
                    if psutil.Process(pid).name() == "sftp_push.py":
                        LOGGER.info(
                            "Script instance is already running. Exiting.")
                        sys.exit(0)
            except ValueError:
                LOGGER.warning(
                    "Invalid contents were written to lockfile located at: {}".format(lockfile))
            LOGGER.info(
                "Deleting stale lockfie located at: {}".format(lockfile))
        os.remove(lockfile)

    # Create lock file and write own PID into it
    with open(lockfile, "w+") as f:
        f.write(str(myPID))
        f.close()


def authenticate_pw(user:str, pw: str, transport:paramiko.Transport):
    # Authenticate SFTP client by using password authentication
    transport.auth_password(user, pw)
    sftp_session = SFTPDirClient.from_transport(transport)
    return sftp_session


def authenticate_identity(user:str, identity_file:str, transport:paramiko.Transport):
    # Authenticate SFTP client by using public key authentication
    try:
        private_key = paramiko.RSAKey.from_private_key_file(identity_file)
    except Exception as e:
        LOGGER.critical(
            "Failed to load private key file {} (Exception: {})".format(identity_file, e))
        raise
    agent = paramiko.Agent()
    agent_keys = agent.get_keys() + (private_key,)
    if len(agent_keys) == 0:
        raise RuntimeError(
            "No private key available for SFTP authentication"
        )
    for key in agent_keys:
        try:
            transport.auth_publickey(user, key)
            break
        except paramiko.SSHException as e:
            pass
    if not transport.is_authenticated():
        raise RuntimeError(
            f"Could not authenticate against SFTP server {transport.getpeername()[0]}. No suitable public key available."
        )

    sftp_session = paramiko.SFTPDirClient.from_transport(transport)
    LOGGER.debug("SFTP session successfully established")
    return sftp_session


def connect(server_address: str, port: int, user: str, pw: str, identity_file: str, proxy: str):

    # Determine if the host key of the server is already known to the client
    try:
        host_keys = paramiko.util.load_host_keys(
            os.path.expanduser('~/.ssh/known_hosts')
        )
    except IOError:
        try:
            # try ~/ssh/ too, e.g. on windows
            host_keys = paramiko.util.load_host_keys(
                os.path.expanduser('~/ssh/known_hosts')
            )
        except IOError:
            LOGGER.warning("No known_hosts file found")

    if server_address in host_keys:
        host_key_type = host_keys[server_address].keys()[0]
        LOGGER.info(
            "Using host key of type {} for SFTP connection to {}:{}".format(
                host_key_type, server_address, port)
        )

    # Negotiate SSH2 connection between server and client
    try:
        if proxy:
            proxy = paramiko.ProxyCommand(
                "ssh -W {}:{} {}".format(server_address, port, proxy))
            transport = paramiko.Transport(proxy)
            LOGGER.debug(f"Configured connection to SFTP server '{server_address}:{port}' using proxy '{proxy}'")
        else:
            transport = paramiko.Transport((server_address, port))
            LOGGER.debug(f"Configured connection to SFTP server '{server_address}:{port}'")

        transport.start_client()

        # Authenticate against SFTP server
        if identity_file:
            sftp_session = authenticate_identity(
                user, identity_file, transport)
        else:
            sftp_session = authenticate_pw(user, pw, transport)
        # Paramiko logs the success of this operation as "INFO" but without any information about the connection
        LOGGER.info(f"Connected to SFTP server {server_address}:{port} with user {user}")
        return sftp_session

    except socket.gaierror as ex:
        LOGGER.error("Invalid SFTP server: '{}'. Aborting.".format(server_address))
        sys.exit(1)
    except paramiko.ssh_exception.SSHException:
        LOGGER.error("Server '{}' not reachable at port '{}'. Aborting".format(
            server_address, port))
        sys.exit(1)


def main(argv):
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
        LOGGER.debug("sftp_pypeline.py started, started Logging now.")

        # check if a lock file exists
        if args.lock:
            process_lock(args.lock)
            lock_created = True
            LOGGER.debug("Lockfile created at:'{}'".format(args.logfile))

        if args.identity:
            if not os.path.isfile(args.identity):        
                LOGGER.critical(f"Identity file at '{args.identity}' could not be found. Aborting.")
                sys.exit(1)
            else:
                LOGGER.debug(f"Identity file found at '{args.identity}'")

        files_moved = 0
        # SFTP connection
        sftp_session = connect(args.server, args.port, args.user,
                               args.pw, args.identity, args.proxy)

        # Upload file or directory to remote sftp location
        if args.put:
            if not sftp_session.dirExists(args.remote):
                LOGGER.critical(f"Remote target directory does not exist: '{args.remote}'. Aborting.")
                sys.exit(1)
            if not os.path.exists(args.local):
                LOGGER.critical(f"Local source directory or file does not exist: '{args.local}'. Aborting.")
                sys.exit(1)
            files_moved = sftp_session.put_item(
                args.local, args.remote, args.overwrite, args.delete)

        # Download file or directory from remote sftp location
        elif args.get:
            if not sftp_session.exists(args.remote):
                LOGGER.critical(f"Remote source file or directory does not exist: '{args.remote}'. Aborting.")
                sys.exit(1)
            if not os.path.isdir(args.local):
                LOGGER.critical(f"Local target directory does not exist: '{args.local}'. Aborting.")
                sys.exit(1)
            files_moved = sftp_session.get_item(
                args.local, args.remote, args.overwrite, args.delete)
        LOGGER.info(f"Uploaded a total of {files_moved} files")

        # Disconnect
        try:
            sftp_session.close()
            LOGGER.info("Successfully closed connection to SFTP server")
        except Exception as e:
            LOGGER.error("Failed to close connection to SFTP server due to unknown reason")
            
    except Exception as ex:
        raise ex
        exc_type, exc_value, exc_traceback = sys.exc_info()
        st = traceback.format_exception(
            exc_type, exc_value, exc_traceback, limit=8)
        LOGGER.critical(f"A fatal error occurred. Error message was: {ex} (stack trace: {st}). Aborting.")
        sys.exit(1)
    
    finally:
        if lock_created:
            # Remove lock file
            if os.path.isfile(args.lock):
                os.remove(args.lock)
                LOGGER.info("End of SFTP pushing process, lock File was removed")
            else:
                LOGGER.warning(f"No lock file was found at '{args.lock}', no clean up was conducted")


if __name__ == '__main__':
    main(sys.argv[1:])
