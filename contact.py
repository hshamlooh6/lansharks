#!/usr/bin/env python3
import re
import secrets

from common import db, esc, hash_password, is_post, page, read_form, redirect, respond

FIELDS = ["firstName", "lastName", "companyName", "address", "city", "state", "zipCode", "email", "phone"]


def unique_username(conn, first, last):
    base = re.sub(r"[^a-z0-9]", "", (first[:1] + last).lower()) or "customer"
    candidate, number = base, 1
    while conn.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)).fetchone():
        number += 1
        candidate = f"{base}{number}"
    return candidate


if not is_post():
    redirect("contact.html")
else:
    form = read_form()
    values = {field: form.get(field, "").strip() for field in FIELDS}
    comments = form.get("comments", "").strip()

    if not all(values.values()):
        respond(page("Missing Information", """<h1>Missing Information</h1>
<p>Please fill in every field marked as required.</p>
<p>Click <a href="contact.html">here</a> to go back to the form.</p>"""), "400 Bad Request")
    else:
        password = secrets.token_urlsafe(9)
        with db() as conn:
            cursor = conn.execute(
                """INSERT INTO customers
                   (firstName, lastName, companyName, address, city, state, zipCode, email, phone, comments)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (*values.values(), comments),
            )
            username = unique_username(conn, values["firstName"], values["lastName"])
            conn.execute(
                "INSERT INTO users (username, password, type, customerNumber) VALUES (?, ?, 'c', ?)",
                (username, hash_password(password), cursor.lastrowid),
            )

        respond(page("Account Created", f"""<h1>Account Created</h1>
<p>Welcome to LAN Sharks, {esc(values['firstName'])} {esc(values['lastName'])}.
An account has been created for {esc(values['companyName'])}.</p>
<div class="notice">
  <p><strong>User name:</strong> {esc(username)}<br>
  <strong>Password:</strong> <code>{esc(password)}</code></p>
</div>
<p>Keep these somewhere safe, then <a href="login.html">log in</a>.
You can change the password from your account page.</p>"""))
