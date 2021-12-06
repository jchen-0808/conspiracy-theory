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

def calcpref(user):
    count = {politics: "0", history: "0", aliens: "0", popculture: "0", miscellaneous: "0"}
    likes = db.execute("SELECT genre FROM likehistory WHERE user = ?", user)
    for x in likes:
        if(x == "politics"):
            count[politics] = count[politics] + 1
        elif(x == "history"):
            count[history] = count[history] + 1
        elif(x == "aliens"):
            count[aliens] = count[aliens] + 1
        elif(x == "pop-culture"):
            count[popculture] = count[popculture] + 1
        else:
            count[miscellaneous] = count[miscellaneous] + 1
    return max(stats.items(), key=operator.itemgetter(1))[0]

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
    theories = db.execute("SELECT * FROM theories ORDER BY upvotes LIMIT 5")

    return render_template("home.html", theories=theories)


@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    if request.method == "POST":
        name = request.form.get("name")
        content = request.form.get("post")

        # ensures all fields are filled
        if name == "" or content == "":
            return apology("Please complete all fields")
        
        user = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
        username = user[0]["username"]

        date = db.execute("SELECT DATETIME()")

        db.execute("INSERT INTO theories (name, user, content, date, id) VALUES (?, ?, ?, ?, ?)", name, username, content, date[0]["DATETIME()"], session["user_id"])
        
        # Redirect user to home page
        return redirect("/recents")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        genres = {"politics", "history", "aliens", "pop-culture", "miscellaneous"}
        return render_template("post.html", genres=genres)


@app.route("/your-posts")
@login_required
def history():

    pastTheories = db.execute("SELECT * FROM theories WHERE id = ? ORDER BY date DESC", session["user_id"])

    return render_template("history.html", pastTheories=pastTheories)


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
    if request.method == "POST":
        return redirect("/questions")
    
    else:
        return render_template("quiz.html")

@app.route("/questions", methods=["GET", "POST"])
def questions():
    if request.method == "POST":
        q1 = int(request.form.get("q1"))
        q2 = int(request.form.get("q2"))
        q3 = int(request.form.get("q3"))
        q4 = int(request.form.get("q4"))
        q5 = int(request.form.get("q5"))
        q6 = int(request.form.get("q6"))
        q7 = int(request.form.get("q7"))
        q8 = int(request.form.get("q8"))
        q9 = int(request.form.get("q9"))
        q10 = int(request.form.get("q10"))

        aliens = q1 + q6
        politics = q2 + q9
        history = q4 + q8
        misc = q5 + q3
        popCult = q10 + q7
        
        db.execute("INSERT INTO quiz (username, alien, politics, history, misc, popcult) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], aliens, politics, history, misc, popCult)

        minScore = 10
        maxScore = 50

        userMin = aliens + politics + history + misc + popCult

        if userMin == minScore:
            db.execute("UPDATE quiz SET skeptic = ? WHERE username = ?", 1, session["user_id"])
        elif userMin == maxScore:
            db.execute("UPDATE quiz SET misc = ? WHERE username = ?", 100, session["user_id"])

        return render_template("results.html")
        
    else:
        return render_template("questions.html")


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


@app.route("/recents", methods=["GET", "POST"])
@login_required
def recents ():
    if request.method == "GET":
        data = db.execute("SELECT * FROM theories ORDER BY date DESC LIMIT 10")
        return render_template("recents.html", data=data)
    
    else:
        name = request.form.get("name")
        genre = request.form.get("genre")
        id = session["user_id"]

        if request.form["like"] == "like":
            updatedvalue = int(request.form.get("likes")) + 1
            newpref = calcpref(id)
            db.execute("UPDATE theories SET upvotes = ? WHERE name = ?", updatedvalue, name)
            db.execute("INSERT INTO likehistory (theory, user, like, genre) VALUES (?, ?, ?, ?)", name, id, 1, genre)
            db.execute("UPDATE users SET preference = ? WHERE id = ?", newpref, id)

        elif request.form["dislike"] == "dislike":
            updatedvalue = int(request.form.get("dislikes")) + 1
            db.execute("UPDATE theories SET downvotes = ? WHERE name = ?", updatedvalue, name)
            db.execute("INSERT INTO likehistory (theory, user, like, genre) VALUES (?, ?, ?, ?)", name, username, 0, genre)
        return redirect("/recents")


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
