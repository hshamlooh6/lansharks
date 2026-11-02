#!/usr/bin/env python3
from common import (check_password, db, esc, full_name, hash_password, is_post, load_person,
                    page, read_form, require_user, respond, show_message)

user = require_user()
name = full_name(load_person(user))

if not is_post():
    respond(page("Change Password", f"""<h1>{esc(name)}</h1>
<p class="subtitle">User name: {esc(user['username'])}</p>
<form method="post" action="change_password.py" class="narrow">
  <label>Current password
    <input type="password" name="current" autocomplete="current-password" required>
  </label>
  <label>New password
    <input type="password" name="new" autocomplete="new-password" required>
  </label>
  <label>Confirm new password
    <input type="password" name="confirm" autocomplete="new-password" required>
  </label>
  <button type="submit">Change Password</button>
</form>
<p><a href="dashboard.py">Back to my account</a></p>"""))
else:
    form = read_form()
    new_password = form.get("new", "")

    if not check_password(form.get("current", ""), user["password"]):
        problem = "The current password you entered is incorrect."
    elif not new_password:
        problem = "The new password cannot be empty."
    elif new_password != form.get("confirm", ""):
        problem = "The new password and the confirmation do not match."
    else:
        problem = None

    if problem:
        show_message(
            "Something Went Wrong",
            f"Uh oh, something went wrong. Your password was not changed. {problem}",
            "dashboard.py",
            "to return to the main page.",
        )
    else:
        with db() as conn:
            conn.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(new_password), user["username"]))
        respond(page("Password Changed", f"""<h1>Password Changed!</h1>
<p>{esc(name)}, you have successfully changed your password!</p>
<p><a href="dashboard.py">Click here to go back to the main page</a></p>"""))
