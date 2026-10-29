# Network Security IP Range Scanner

> **Educational project.** Use only on systems you own or are explicitly authorised to test.

## 1. Problem Statement
To audit your own network you need to know which devices answer and which common services they expose, without scanning anything you do not own.

## 2. Objective
Build a limited, safe scanner that checks a small set of TCP ports across a private IPv4 range and lists reachable hosts.

## 3. Features
- Accepts a private IPv4 CIDR range (e.g. `192.168.1.0/24`)
- Rejects public, IPv6 and malformed ranges
- Hard limit of 256 addresses per run
- Checks at most 10 TCP ports (default 22, 80, 443, 8080)
- Lists reachable hosts and their open ports
- Requires `--confirm-authorized` to run

## 4. Technologies Used
- Python 3 standard library (`ipaddress`, `socket`, `argparse`, `concurrent.futures`)

## 5. Folder Structure
```text
03-network-security-ip-range-scanner/
  .gitignore
  LICENSE
  README.md
  ip_range_scanner.py
  requirements.txt
```

## 6. Installation Steps
1. Install **Python 3.8 or newer** from <https://www.python.org/downloads/> (tick "Add Python to PATH" on Windows).
2. Open a terminal **inside this project folder**.
3. No extra packages are needed (standard library only), so there is nothing to `pip install`.

## 7. Commands to Run
```bash
python ip_range_scanner.py 192.168.1.0/24 --confirm-authorized
python ip_range_scanner.py 192.168.1.0/24 -p 22,80,443 -t 0.5 --confirm-authorized
python ip_range_scanner.py --help
```

## 8. How It Works
1. The CIDR is parsed with `ipaddress`; only private IPv4 ranges with at most 256 addresses pass.
2. For every address each chosen port gets one TCP connect attempt.
3. A host is **reachable** when a port is open or actively refuses the connection (something replied). Timeouts alone are shown as no response.
4. Reachable hosts are printed with their open ports.

## 9. Example Input / Output
Real output captured against the loopback range `127.0.0.0/30` with a temporary local listener:
```text
$ python ip_range_scanner.py 127.0.0.0/30 -p <listener-port>,9 --confirm-authorized
Scanning 127.0.0.0/30 (2 addresses) on ports [9, 52527], timeout 0.5s

HOST              OPEN PORTS
127.0.0.1         52527
127.0.0.2         (none of the listed ports)

Done in 0.00s: 2 of 2 addresses reachable.
```
Public range: `python ip_range_scanner.py 8.8.8.0/24 --confirm-authorized` prints `Error: 8.8.8.0/24 is not a private range...`

## 10. Screenshots
_Add your own screenshots after running the project (do not use screenshots from elsewhere)._

| Description | Screenshot |
|---|---|
| Main screen / output | `docs/screenshot-1.png` _(placeholder)_ |
| Another feature | `docs/screenshot-2.png` _(placeholder)_ |

## 11. Demo Link
`<YOUR-DEMO-LINK-HERE>` _(placeholder: this project has not been deployed by the author of this template)_

## 12. Security Measures
- Private ranges only (RFC 1918 and loopback)
- Address and port count limits
- Explicit authorisation flag
- Timeout and worker limits; no exploitation or stealth features

## 13. Limitations
- Hosts that silently drop packets look unreachable
- IPv4 and TCP only
- No ping/ARP discovery
- Only up to /24-sized ranges

## 14. Future Improvements
- ARP-based discovery on local networks
- Export to CSV
- Hostname lookup (reverse DNS)
- Scan history comparison

## 15. GitHub Upload Instructions
1. Sign in at <https://github.com> and click **New repository** (the **+** icon, top right).
2. Name it `03-network-security-ip-range-scanner`, choose Public or Private, and click **Create repository**.
3. On the new repo page click **uploading an existing file**.
4. Drag in the **contents** of this folder (files and sub-folders, *not* the ZIP itself). Hidden files such as `.gitignore` must be included.
5. Write a commit message such as `Initial commit` and click **Commit changes**.
6. Edit `LICENSE` and replace `<YOUR NAME>`; add real screenshots to a `docs/` folder and update the README.

## License
MIT. See `LICENSE`.
