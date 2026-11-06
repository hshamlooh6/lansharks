# LAN Sharks: Packet Capture Threat Detection

A small customer portal for LAN Sharks, a fictional security company that looks after small office and home office (SOHO) networks.

Customers upload Wireshark captures exported as CSV. When they sign in, the portal imports any new captures into a SQLite database, checks the packets for ARP poisoning and SYN floods, and lists what it found on their account page. Employees get their own page and the same password tools.

I built the first version as the capstone for the Python Scripting Fundamentals course in the Akamai Network Engineering Professional Certificate, then reworked it into this standalone project.

## Features

- **Sign-up form** that creates a customer record and a login. The user name is the first initial plus the last name (a number is added if it is already taken), and a random password is shown once.
- **Login for customers and employees.** An "I am an employee" checkbox has to match the account type. A wrong password and a wrong checkbox get different messages.
- **Employee page** with name, position, email, user name and a change password link.
- **Customer page** with name, company, a table of detected attacks, and links to update contact details or change the password.
- **Log import.** Every file in `logs/` named `<customerNumber>_<anything>.csv` is loaded into the `incidents` table and renamed to `<name>_<timestamp>.old`, so it is only processed once.
- **Sessions.** After logging in, every page finds the user from a session cookie, so nobody has to log in again to get back to their main page.

## How detection works

**ARP poisoning.** ARP packets are grouped by source MAC address and date. The IP address at the end of each Info field is the address that MAC is claiming. If one MAC claims two or more different IPs on the same day, the page reports the MAC, the number of packets and the time of the first one.

**SYN flood.** A packet counts when its Info field contains `[SYN]` and its source and destination IP are the same. The attacked port is the number right before the flag. The page shows one row per port per day with the number of packets. The flag is a parameter of `find_packet_floods()`, so other flags can be checked the same way.

## Run it on your own computer

You only need Python 3.8 or newer. There is nothing to install with pip.

```bash
git clone https://github.com/hshamlooh6/lansharks.git
cd lansharks
python3 server.py
```

On Windows use `python server.py`. Then open <http://127.0.0.1:8000>.

The first run creates `python.db`. To start over with a clean database, run `python3 createdatabase.py`. Processed captures are renamed to `.old`; `git restore logs` brings the samples back.

### Demo accounts

Every demo account uses the password `P@ssw0rd`.

| User name | Account | Who |
|-----------|---------|-----|
| `mali` | Employee | Mohammed Ali, President |
| `hhassan` | Employee | Hussain Hassan, Vice President |
| `fammar` | Customer 1 | Fatima Ammar, Barakah Enterprise |
| `bhussain` | Customer 2 | Batool Hussain, Noor Technologies |
| `ksalman` | Customer 3 | Khadijah Salman, Al-Hadi Solutions |

`logs/1_office_capture.csv` contains an ARP poisoning attack and two days of SYN floods for customer 1. `logs/2_branch_capture.csv` contains a SYN flood on port 443 for customer 2. Customer 3 has no captures, so their table is empty.

## Tests

```bash
python -m unittest discover -s tests -v
```

On Mac and Linux use `python3`. The 34 tests finish in a few seconds and need nothing beyond the standard library.

- `tests/test_detection.py` checks the ARP poisoning and SYN flood rules directly, including the cases that should *not* be flagged: SYN-ACK replies, normal connections between two hosts, and claims spread across different days.
- `tests/test_site.py` copies the project to a temporary folder, starts the server on a free port and uses the site the way a person would: signing up, logging in with the wrong checkbox or password, changing a password, updating contact details, importing a new capture and trying to download private files. Your own database and logs are never touched.

## Project layout

| File | What it does |
|------|--------------|
| `index.html`, `login.html`, `contact.html`, `style.css` | Static pages |
| `login.py` | Checks the user name, password and employee checkbox, then starts a session |
| `dashboard.py` | Employee or customer main page; imports new logs for customers |
| `change_password.py` | Change password form and update |
| `update_contact.py` | Customer contact details form and update |
| `contact.py` | New customer sign-up |
| `logout.py` | Ends the session |
| `logprocessor.py` | CSV import and attack detection |
| `common.py` | Database access, password hashing, sessions and page layout |
| `createdatabase.py` | Builds `python.db` with the demo data |
| `server.py` | Small local web server that runs the scripts the way Apache CGI would |
| `tests/` | Unit tests for the detection rules and end-to-end tests for the whole site |

## Security choices

- Passwords are stored as salted PBKDF2-SHA256 hashes, never as plain text.
- Logging in creates a random session token in an `HttpOnly`, `SameSite=Lax` cookie that expires after eight hours. Pages never trust a user name passed in the URL.
- Every SQL query uses parameters, and every value from the database is HTML-escaped before it is shown.
- `server.py` only runs the six page scripts and only serves `.html` and `.css` files, so the database, logs and helper scripts can't be downloaded.

## Deploying on Apache (Ubuntu)

```bash
sudo apt install apache2
sudo a2enmod cgid
sudo cp -r *.html *.css *.py logs /var/www/html/
cd /var/www/html
sudo python3 createdatabase.py
sudo chown -R www-data:www-data /var/www/html
sudo chmod 755 /var/www/html/*.py
```

Add this inside the `<VirtualHost *:80>` block of `/etc/apache2/sites-enabled/000-default.conf`, then run `sudo systemctl restart apache2`:

```apache
<Directory /var/www/html>
    Options +ExecCGI -Indexes
    AddHandler cgi-script .py
    DirectoryIndex index.html
</Directory>

<FilesMatch "^(common|logprocessor|createdatabase|server)\.py$|\.(db|csv|old)$">
    Require all denied
</FilesMatch>
```

The second block stops visitors from downloading the database or the packet captures, or from running the helper scripts directly.

---

LAN Sharks is a fictional company. All names, addresses and packet captures in this repository are made up.
