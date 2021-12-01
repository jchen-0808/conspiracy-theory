import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///conspiracy.db")



@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def home():
    return render_template("home.html")


@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    return render_template("post.html")


@app.route("/history")
@login_required
def history():
    return render_template("history.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz():
    return render_template("quiz.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    # User submitted form
    if request.method == "POST":

        # Assigns values to variable for simplification
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # ensures all fields are filled
        if username == "" or password == "" or confirmation == "":
            return apology("Please enter a value for all fields")

        # enures passwords match
        elif password != confirmation:
            return apology("Your passwords did not match")
            
        # generates hash
        hash = generate_password_hash(password)

        # Uses Unique requirement in SQL to test if username is unique. If not, program will go to apology
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        except ValueError:
            return apology("Username already taken")
        
        # creates session ID
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    # get method to render form
    else:
        return render_template("register.html")


@app.route("/trending", methods=["GET", "POST"])
@login_required
def trending():
    return render_template("trending.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        newPassword = request.form.get("new password")
        confirm = request.form.get("confirm")

        if newPassword == confirm:
            # generates hash
            hash = generate_password_hash(newPassword)

            # Updates users hash in the database
            db.execute("UPDATE users SET hash = ? where id = ?", hash, session["user_id"])

            return redirect("/")

    else:
        return render_template("change.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
