# Instance 18: Polluted stdout in .bashrc Breaking Binary Subsystems (SFTP/SCP)

## 1. Problem Description
* Interactive shell login (`ssh target`) succeeds completely and displays a friendly banner:
  ```text
  Welcome to Cluster Node 4! All systems operational.
  ```
* Automated operations (`scp`, `sftp`, Ansible, `git clone ssh://...`) fail with cryptic binary protocol framing errors:
  ```text
  Received message too long 1466262131
  fatal: protocol error: bad line length 32
  ```

## 2. Root Cause
In `/home/deploy/.bashrc`, an unbuffered `echo` or script runs for non-interactive shells. `1466262131` in ASCII is `Welc` (`0x57 0x65 0x6c 0x63`), the first 4 bytes of `"Welcome"`. The SFTP client expects a 4-byte packet length integer, interprets `"Welc"` as a 1.4GB packet size, and aborts.

## 3. Sound Remediation
Wrap shell banner outputs in an interactive TTY guard:
```bash
if [ -t 0 ]; then
    echo "Welcome to Cluster Node 4! All systems operational."
fi
```
