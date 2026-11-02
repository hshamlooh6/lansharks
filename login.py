#!/usr/bin/env python3
from common import check_password, db, is_post, read_form, redirect, show_message, start_session

WRONG_BOX = (
    "Uh oh, something went wrong. If you are an employee, make sure you checked the employee box "
    "on the login page. If you are not, please do not check the box."
)

if not is_post():
    redirect("login.html")
else:
    form = read_form()
    username = form.get("username", "").strip().lower()
    password = form.get("password", "")
    says_employee = "employee" in form

    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user is None or not check_password(password, user["password"]):
        show_message("Authentication Failed", None, "login.html", "to retry.")
    elif (user["type"] == "e") != says_employee:
        show_message("Something Went Wrong", WRONG_BOX, "login.html", "to retry.")
    else:
        redirect("dashboard.py", [start_session(user["username"])])
