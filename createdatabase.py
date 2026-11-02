#!/usr/bin/env python3
import os
import sqlite3
import sys

from common import DB_PATH, hash_password

DEFAULT_PASSWORD = "P@ssw0rd"

SCHEMA = """
CREATE TABLE customers (
    customerNumber INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    companyName TEXT NOT NULL,
    address TEXT NOT NULL,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    zipCode TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    comments TEXT DEFAULT ''
);

CREATE TABLE employees (
    employeeNumber INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    position TEXT NOT NULL,
    email TEXT NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('e', 'c')),
    customerNumber INTEGER REFERENCES customers(customerNumber)
);

CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customerNumber INTEGER NOT NULL,
    packetNo TEXT,
    time TEXT,
    source TEXT,
    destination TEXT,
    protocol TEXT,
    length TEXT,
    info TEXT,
    destPort TEXT,
    sourceFile TEXT
);

CREATE INDEX incidents_by_customer ON incidents (customerNumber, time);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created TEXT NOT NULL
);
"""

EMPLOYEES = [
    ("mali", "Mohammed", "Ali", "President", "mali@lansharks.example"),
    ("hhassan", "Hussain", "Hassan", "Vice President", "hhassan@lansharks.example"),
]

CUSTOMERS = [
    ("fammar", "Fatima", "Ammar", "Barakah Enterprise", "12 Harbor Road", "Springfield", "IL", "62701",
     "fatima@barakah.example", "555-0101"),
    ("bhussain", "Batool", "Hussain", "Noor Technologies", "48 Lakeview Avenue", "Riverton", "WY", "82501",
     "batool@noortech.example", "555-0102"),
    ("ksalman", "Khadijah", "Salman", "Al-Hadi Solutions", "7 Cedar Lane", "Fairview", "OR", "97024",
     "khadijah@alhadi.example", "555-0103"),
]


def create_database():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    for username, first, last, position, email in EMPLOYEES:
        conn.execute(
            "INSERT INTO employees (username, firstName, lastName, position, email) VALUES (?, ?, ?, ?, ?)",
            (username, first, last, position, email),
        )
        conn.execute(
            "INSERT INTO users (username, password, type) VALUES (?, ?, 'e')",
            (username, hash_password(DEFAULT_PASSWORD)),
        )

    for username, *details in CUSTOMERS:
        cursor = conn.execute(
            """INSERT INTO customers
               (firstName, lastName, companyName, address, city, state, zipCode, email, phone)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            details,
        )
        conn.execute(
            "INSERT INTO users (username, password, type, customerNumber) VALUES (?, ?, 'c', ?)",
            (username, hash_password(DEFAULT_PASSWORD), cursor.lastrowid),
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    if "GATEWAY_INTERFACE" in os.environ:
        sys.exit("createdatabase.py must be run from a terminal, not through the web server.")
    create_database()
    print(f"Database created at {DB_PATH}")
    print(f"Every account uses the password {DEFAULT_PASSWORD}")
    print("Employees: " + ", ".join(e[0] for e in EMPLOYEES))
    print("Customers: " + ", ".join(c[0] for c in CUSTOMERS))
