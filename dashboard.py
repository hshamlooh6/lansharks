#!/usr/bin/env python3
from common import esc, full_name, load_person, page, require_user, respond
from logprocessor import detect_attacks, import_logs


def employee_view(person, username):
    return f"""<h1>{esc(full_name(person))}</h1>
<p class="subtitle">{esc(person['position'])}</p>
<dl class="details">
  <dt>Email</dt><dd>{esc(person['email'])}</dd>
  <dt>User name</dt><dd>{esc(username)}</dd>
</dl>
<div class="actions">
  <a class="button" href="change_password.py">Change Password</a>
  <a class="button secondary" href="logout.py">Log Out</a>
</div>"""


def customer_view(person, attacks):
    rows = "\n".join(
        f"<tr><td>{esc(a['type'])}</td><td>{esc(a['info'])}</td>"
        f"<td>{esc(a['count'])}</td><td>{esc(a['time'])}</td></tr>"
        for a in attacks
    ) or '<tr><td colspan="4" class="empty">No attacks detected in your uploaded captures.</td></tr>'

    return f"""<h1>{esc(full_name(person))}</h1>
<p class="subtitle">{esc(person['companyName'])}</p>
<div class="actions">
  <a class="button" href="update_contact.py">Update Contact Information</a>
  <a class="button" href="change_password.py">Change Password</a>
  <a class="button secondary" href="logout.py">Log Out</a>
</div>
<h2>Detected attacks</h2>
<div class="table-wrap">
<table>
  <thead><tr><th>Attack Type</th><th>Info</th><th>Attacks</th><th>Date-Time</th></tr></thead>
  <tbody>
{rows}
  </tbody>
</table>
</div>"""


user = require_user()
person = load_person(user)

if user["type"] == "e":
    respond(page("Employee", employee_view(person, user["username"])))
else:
    import_logs()
    respond(page("My Account", customer_view(person, detect_attacks(user["customerNumber"]))))
