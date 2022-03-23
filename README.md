# sftp-pypeline
A little script that allows you to transfer data from and to sftp with some convenience features

## Installation
This script is currently not part of the official pip repositories. So you have to install it locally:

```bash
git clone https://github.com/SirGibihm/sftp-pypeline
pip install -e sftp_pypeline
```

You can then use the script from your normal path environment:
* **Windows**: `sftp_pype.exe --help`
* **Linux**: `sftp_pype --help`

## Parameters

```
Script to robustly up- and download data from and to SFTP shares
options:
  -h, --help            show this help message and exit
  --put                 Put file or directory to server
  --get                 Fetch file or directory from server
  -s SERVER, --server SERVER
                        SFTP server IP
  -p PORT, --port PORT  SFTP server port
  -u USER, --user USER  SFTP user
  --pw PW               Password for SFTP user password
  -i IDENTITY, --identity IDENTITY
                        Identity file for SFTP user (SSH private key)
  -l LOCAL, --local LOCAL
                        Local Directory where stuff is put, defaults (Default: ./)
  -r REMOTE, --remote REMOTE
                        Destination on where to put files (Default: ./)
  --proxy PROXY         Proxy SSH server
  -k LOCK, --lock LOCK  Lock file, no lock collision is observed if not given.
  -g LOG_FILE, --log-file LOG_FILE
                        Log file, logs to console if no file is given (Default)
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Log Level (Default INFO)
  -w, --overwrite       Overwrite files at destination if they allready exist
  -d, --delete          Delete files from local directory after pushing

```

## Usage Examples

### Upload from Windows using password based authentication
Upload a Alices Directory to a remote SFTP server for which we only have an IP. Don't delete the local files after upload but overwrite existing files based on their filenames. Create a lock file so other executions of this script (e. g. using a Cron Job) can check if the script is still running. If files already exist, overwrite them. Print all Logging to console at level `INFO`.
```bash
sftp_pypeline.exe --put -s 172.10.20.30 -u alice --pw alices_password -l "C:\Users\alice\Documents\my dir\ " -r /home/bob/ -k alice_documents_mydir.lock -w
```

### Download to Linux using a keyfile
Download the file `evil_virus.sh` from the `thats-bad.com:666` to the local directory `/home/alice`. Document everything about the process in the current working directory in the file `logfile.log`. Delete the remote file after downloading it.
```bash
sftp_pypeline --get -s thats-bad.com -p 666 -u lucy --pw eves_password -l /home/alice/ -r /home/eve/evil_virus.sh -g logfile.log --log-level DEBUG -d
```
## TBDs:
- Check if Proxy authentication is working as intended
- Check if pushing from Linux to Windows does not lead to any pathing issues
