#!/usr/bin/env python3
from common import db, esc, full_name, is_post, load_person, page, read_form, redirect, require_user, respond

FIELDS = [
    ("companyName", "Company name", "text"),
    ("address", "Address", "text"),
    ("city", "City", "text"),
    ("state", "State", "text"),
    ("zipCode", "ZIP code", "text"),
    ("email", "Email", "email"),
    ("phone", "Phone", "tel"),
]


def contact_form(user, values, note=""):
    inputs = "\n".join(
        f'  <label>{label}\n    <input type="{kind}" name="{field}" value="{esc(values.get(field) or "")}" required>\n  </label>'
        for field, label, kind in FIELDS
    )
    return f"""<h1>Update Contact Information</h1>
<p class="subtitle">User name: {esc(user['username'])}</p>
{note}
<form method="post" action="update_contact.py" class="grid-2">
{inputs}
  <div class="full"><button type="submit">Update Contact Information</button></div>
</form>
<p><a href="dashboard.py">Back to my account</a></p>"""


user = require_user()

if user["type"] != "c":
    redirect("dashboard.py")
elif not is_post():
    respond(page("Update Contact Information", contact_form(user, dict(load_person(user)))))
else:
    form = read_form()
    values = {field: form.get(field, "").strip() for field, _, _ in FIELDS}

    if not all(values.values()):
        note = '<p class="notice">Every field is required. Nothing was changed.</p>'
        respond(page("Update Contact Information", contact_form(user, values, note)), "400 Bad Request")
    else:
        assignments = ", ".join(f"{field} = ?" for field, _, _ in FIELDS)
        with db() as conn:
            conn.execute(
                f"UPDATE customers SET {assignments} WHERE customerNumber = ?",
                (*values.values(), user["customerNumber"]),
            )
        respond(page("Contact Information Updated", f"""<h1>Contact Information Updated!</h1>
<p>{esc(full_name(load_person(user)))}, you have successfully changed your contact information!</p>
<p><a href="dashboard.py">Click here to go back to the main page</a></p>"""))
