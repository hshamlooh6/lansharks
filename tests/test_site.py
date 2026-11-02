import http.cookiejar
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from collections import namedtuple
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
PASSWORD = "P@ssw0rd"
ROW = re.compile(r"<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td></tr>")

OFFICE_CAPTURE = """No.,Time,Source,Destination,Protocol,Length,Info
1,2026-03-14 09:12:03,00:1a:2b:3c:4d:5e,ff:ff:ff:ff:ff:ff,ARP,42,Who has 192.168.1.1? Tell 192.168.1.20
2,2026-03-14 09:12:03,00:0c:29:aa:10:01,00:1a:2b:3c:4d:5e,ARP,60,192.168.1.1 is at 00:0c:29:aa:10:01
3,2026-03-14 09:13:10,08:00:2b:ef:ab:7c,ff:ff:ff:ff:ff:ff,ARP,42,192.168.1.1 is at 08:00:2b:ef:ab:7c
4,2026-03-14 09:13:11,08:00:2b:ef:ab:7c,ff:ff:ff:ff:ff:ff,ARP,42,192.168.1.20 is at 08:00:2b:ef:ab:7c
5,2026-03-14 09:13:12,08:00:2b:ef:ab:7c,ff:ff:ff:ff:ff:ff,ARP,42,192.168.1.35 is at 08:00:2b:ef:ab:7c
6,2026-03-14 10:40:00,192.168.1.10,192.168.1.10,TCP,60,80 → 80 [SYN] Seq=0
7,2026-03-14 10:40:01,192.168.1.10,192.168.1.10,TCP,60,80 → 80 [SYN] Seq=0
8,2026-03-14 10:40:02,192.168.1.10,192.168.1.10,TCP,60,"80 → 80 [SYN, ACK] Seq=0 Ack=1"
9,2026-03-14 10:40:03,192.168.1.20,93.184.216.34,TCP,66,51522 → 443 [SYN] Seq=0
10,2026-03-15 08:05:41,192.168.1.10,192.168.1.10,TCP,60,80 → 80 [SYN] Seq=0
"""

BRANCH_CAPTURE = """No.,Time,Source IP,Destination IP,Protocol,Length,Info,Dest Port
1,2026-05-02 14:21:30,10.0.0.40,10.0.0.40,TCP,60,[SYN] Seq=0,443
2,2026-05-02 14:21:31,10.0.0.40,10.0.0.40,TCP,60,[SYN] Seq=0,443
3,2026-05-02 14:21:32,10.0.0.40,10.0.0.40,TCP,60,[SYN] Seq=0,443
"""

Response = namedtuple("Response", "status url text")


class Client:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        try:
            with self.opener.open(self.base + path, body, timeout=20) as response:
                return Response(response.status, response.geturl(), response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return Response(error.code, error.geturl(), error.read().decode("utf-8", "replace"))

    def get(self, path):
        return self.request(path)

    def post(self, path, data):
        return self.request(path, data)

    def log_in(self, username, password=PASSWORD, employee=False):
        data = {"username": username, "password": password}
        if employee:
            data["employee"] = "yes"
        return self.post("login.py", data)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def sign_up_form(first, last, company="Example Labs"):
    return {
        "firstName": first,
        "lastName": last,
        "companyName": company,
        "address": "4 Test Way",
        "city": "Testville",
        "state": "TS",
        "zipCode": "11111",
        "email": f"{first.lower()}@example.com",
        "phone": "555-0111",
        "comments": "",
    }


class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = Path(tempfile.mkdtemp(prefix="lansharks-test-"))
        cls.site = cls.workdir / "site"
        shutil.copytree(PROJECT, cls.site, ignore=shutil.ignore_patterns("tests", ".git", "python.db*", "__pycache__", "*.zip"))

        cls.logs = cls.site / "logs"
        shutil.rmtree(cls.logs, ignore_errors=True)
        cls.logs.mkdir()
        (cls.logs / "1_office.csv").write_text(OFFICE_CAPTURE, encoding="utf-8")
        (cls.logs / "2_branch.csv").write_text(BRANCH_CAPTURE, encoding="utf-8-sig")
        (cls.logs / "notes.csv").write_text("This file has no customer number.\n", encoding="utf-8")

        port = free_port()
        cls.base = f"http://127.0.0.1:{port}/"
        cls.server_log = open(cls.workdir / "server.log", "w", encoding="utf-8")
        cls.server = subprocess.Popen(
            [sys.executable, str(cls.site / "server.py")],
            cwd=str(cls.site),
            env={**os.environ, "PORT": str(port)},
            stdout=subprocess.DEVNULL,
            stderr=cls.server_log,
        )

        deadline = time.monotonic() + 20
        while True:
            if cls.server.poll() is not None:
                cls.tearDownClass()
                raise RuntimeError("server.py stopped before the tests could start.")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    cls.tearDownClass()
                    raise RuntimeError("server.py did not start within 20 seconds.")
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        if cls.server.poll() is None:
            cls.server.terminate()
            cls.server.wait(timeout=10)
        cls.server_log.close()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def client(self):
        return Client(self.base)

    def query(self, sql, *params):
        conn = sqlite3.connect(str(self.site / "python.db"))
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def import_logs(self):
        self.client().log_in("ksalman")

    def test_public_pages_load(self):
        for path in ["", "login.html", "contact.html", "style.css"]:
            with self.subTest(path=path):
                self.assertEqual(self.client().get(path).status, 200)

    def test_private_files_are_not_served(self):
        for path in ["python.db", "logs/", "logs/1_office.csv", "common.py", "createdatabase.py", "server.py", "README.md"]:
            with self.subTest(path=path):
                self.assertEqual(self.client().get(path).status, 404)

    def test_forms_post_to_python_scripts(self):
        login = self.client().get("login.html").text
        self.assertIn('action="login.py"', login)
        for field in ["username", "password", "employee"]:
            self.assertIn(f'name="{field}"', login)

        contact = self.client().get("contact.html").text
        self.assertIn('action="contact.py"', contact)
        for field in ["firstName", "lastName", "companyName", "address", "city", "state", "zipCode", "email", "phone"]:
            self.assertIn(f'name="{field}"', contact)

    def test_account_pages_require_login(self):
        for path in ["dashboard.py", "change_password.py", "update_contact.py"]:
            with self.subTest(path=path):
                self.assertTrue(self.client().get(path).url.endswith("login.html"))

    def test_employee_who_forgets_the_checkbox_sees_a_hint(self):
        page = self.client().log_in("mali")
        self.assertIn("Something Went Wrong", page.text)
        self.assertIn("employee box", page.text)

    def test_customer_who_ticks_the_checkbox_sees_a_hint(self):
        self.assertIn("Something Went Wrong", self.client().log_in("fammar", employee=True).text)

    def test_wrong_password_and_unknown_user_are_rejected(self):
        self.assertIn("Authentication Failed", self.client().log_in("mali", "wrong", employee=True).text)
        self.assertIn("Authentication Failed", self.client().log_in("nobody", "wrong").text)

    def test_employee_sees_their_profile(self):
        page = self.client().log_in("mali", employee=True)
        self.assertTrue(page.url.endswith("dashboard.py"))
        for text in ["Mohammed Ali", "President", "mali@lansharks.example", "change_password.py"]:
            self.assertIn(text, page.text)

    def test_password_change(self):
        browser = self.client()
        browser.log_in("hhassan", employee=True)
        self.assertEqual(browser.get("change_password.py").text.count('type="password"'), 3)

        wrong_current = browser.post("change_password.py", {"current": "bad", "new": "N3w!pass", "confirm": "N3w!pass"})
        self.assertIn("not changed", wrong_current.text)
        self.assertIn('href="dashboard.py"', wrong_current.text)

        mismatch = browser.post("change_password.py", {"current": PASSWORD, "new": "N3w!pass", "confirm": "Other1"})
        self.assertIn("do not match", mismatch.text)

        changed = browser.post("change_password.py", {"current": PASSWORD, "new": "N3w!pass", "confirm": "N3w!pass"})
        self.assertIn("Password Changed!", changed.text)
        self.assertIn("Hussain Hassan", browser.get("dashboard.py").text)

        self.assertIn("Authentication Failed", self.client().log_in("hhassan", employee=True).text)
        self.assertTrue(self.client().log_in("hhassan", "N3w!pass", employee=True).url.endswith("dashboard.py"))

    def test_log_out_ends_the_session(self):
        browser = self.client()
        browser.log_in("mali", employee=True)
        self.assertTrue(browser.get("logout.py").url.endswith("index.html"))
        self.assertTrue(browser.get("dashboard.py").url.endswith("login.html"))

    def test_customer_report_lists_each_attack(self):
        page = self.client().log_in("fammar")
        self.assertIn("Barakah Enterprise", page.text)
        self.assertEqual(ROW.findall(page.text), [
            ("ARP Poisoning Attack", "08:00:2b:ef:ab:7c", "3 attacks", "2026-03-14 09:13:10"),
            ("Packet Flood", "Packet Flag: [SYN]", "Port: 80 Attacks: 2", "2026-03-14 10:40:00"),
            ("Packet Flood", "Packet Flag: [SYN]", "Port: 80 Attacks: 1", "2026-03-15 08:05:41"),
        ])

    def test_capture_with_other_column_names_and_bom_is_read(self):
        page = self.client().log_in("bhussain")
        self.assertEqual(ROW.findall(page.text), [
            ("Packet Flood", "Packet Flag: [SYN]", "Port: 443 Attacks: 3", "2026-05-02 14:21:30"),
        ])

    def test_customer_without_captures_sees_an_empty_table(self):
        self.assertIn("No attacks detected", self.client().log_in("ksalman").text)

    def test_processed_captures_are_renamed(self):
        self.import_logs()
        names = sorted(path.name for path in self.logs.iterdir())
        self.assertIn("notes.csv", names)
        self.assertFalse([name for name in names if re.match(r"^\d+_.*\.csv$", name)])
        self.assertTrue(any(re.match(r"^1_office_\d{8}-\d{6}\.old$", name) for name in names))
        self.assertTrue(any(re.match(r"^2_branch_\d{8}-\d{6}\.old$", name) for name in names))

    def test_every_packet_is_stored(self):
        self.import_logs()
        counts = dict(self.query("SELECT customerNumber, COUNT(*) FROM incidents WHERE customerNumber IN (1, 2) GROUP BY customerNumber"))
        self.assertEqual(counts, {1: 10, 2: 3})

    def test_contact_update(self):
        browser = self.client()
        browser.log_in("bhussain")
        form = browser.get("update_contact.py").text
        for value in ["Noor Technologies", "48 Lakeview Avenue", "555-0102"]:
            self.assertIn(f'value="{value}"', form)

        updated = browser.post("update_contact.py", {
            "companyName": "Noor <Trading>",
            "address": "99 New Street",
            "city": "Austin",
            "state": "TX",
            "zipCode": "73301",
            "email": "batool@noor.example",
            "phone": "555-0199",
        })
        self.assertIn("Contact Information Updated!", updated.text)
        self.assertIn('href="dashboard.py"', updated.text)

        dashboard = browser.get("dashboard.py").text
        self.assertIn("Noor &lt;Trading&gt;", dashboard)
        self.assertNotIn("<Trading>", dashboard)

        blank = browser.post("update_contact.py", {"companyName": "", "address": "x", "city": "x", "state": "x", "zipCode": "x", "email": "x@example.com", "phone": "x"})
        self.assertEqual(blank.status, 400)

    def test_customers_cannot_open_another_account(self):
        browser = self.client()
        browser.log_in("ksalman")
        page = browser.get("update_contact.py?user=fammar").text
        self.assertIn("Al-Hadi Solutions", page)
        self.assertNotIn("Barakah", page)

    def test_employees_cannot_open_the_contact_form(self):
        browser = self.client()
        browser.log_in("mali", employee=True)
        self.assertTrue(browser.get("update_contact.py").url.endswith("dashboard.py"))

    def test_sign_up_creates_a_working_login(self):
        page = self.client().post("contact.py", sign_up_form("Zainab", "Mahdi"))
        username = re.search(r"User name:</strong> (\w+)", page.text).group(1)
        password = re.search(r"<code>(.*?)</code>", page.text).group(1)
        self.assertEqual(username, "zmahdi")

        user_type, customer_number = self.query("SELECT type, customerNumber FROM users WHERE username = ?", username)[0]
        self.assertEqual(user_type, "c")
        self.assertEqual(self.query("SELECT lastName FROM customers WHERE customerNumber = ?", customer_number), [("Mahdi",)])

        dashboard = self.client().log_in(username, password)
        self.assertTrue(dashboard.url.endswith("dashboard.py"))
        self.assertIn("Zainab Mahdi", dashboard.text)

    def test_sign_up_picks_a_free_user_name(self):
        page = self.client().post("contact.py", sign_up_form("Mohammed", "Ali"))
        self.assertIn("User name:</strong> mali2", page.text)

    def test_sign_up_escapes_html_and_requires_every_field(self):
        page = self.client().post("contact.py", sign_up_form("Sara", "Test", company="<b>Test Co</b>"))
        self.assertIn("&lt;b&gt;Test Co&lt;/b&gt;", page.text)
        self.assertEqual(self.client().post("contact.py", sign_up_form("", "Nobody")).status, 400)

    def test_new_capture_is_imported_on_next_login(self):
        page = self.client().post("contact.py", sign_up_form("Noor", "Saleh"))
        password = re.search(r"<code>(.*?)</code>", page.text).group(1)
        customer_number = self.query("SELECT customerNumber FROM users WHERE username = 'nsaleh'")[0][0]

        capture = self.logs / f"{customer_number}_new.csv"
        capture.write_text(
            "No.,Time,Source,Destination,Protocol,Length,Info\n"
            "1,2027-01-05 11:00:00,10.1.1.5,10.1.1.5,TCP,60,25 > 25 [SYN] Seq=0\n"
            "2,2027-01-05 11:00:01,10.1.1.5,10.1.1.5,TCP,60,25 > 25 [SYN] Seq=0\n",
            encoding="utf-8",
        )
        dashboard = self.client().log_in("nsaleh", password)
        self.assertEqual(ROW.findall(dashboard.text), [
            ("Packet Flood", "Packet Flag: [SYN]", "Port: 25 Attacks: 2", "2027-01-05 11:00:00"),
        ])
        self.assertFalse(capture.exists())

    def test_passwords_are_never_stored_as_plain_text(self):
        for (stored,) in self.query("SELECT password FROM users"):
            self.assertIn("$", stored)
            self.assertNotIn(PASSWORD, stored)


if __name__ == "__main__":
    unittest.main(verbosity=2)
