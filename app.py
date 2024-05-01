import secrets
import sqlite3

from flask import Flask, make_response, request, render_template, redirect
from helper import sanitize

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
con = sqlite3.connect("app.db", check_same_thread=False)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("1/second")
@limiter.limit("10/hour")
@limiter.limit("100/day")
def login():
    cur = con.cursor()
    if request.method == "GET":
        if request.cookies.get("session_token"):
            # parameteriize session tokens
            res = cur.execute("SELECT username FROM users INNER JOIN sessions ON "
                              + "users.id = sessions.user WHERE sessions.token = ?", [request.cookies.get("session_token")])
            user = res.fetchone()
            
            if user:
                return redirect("/home")

        return render_template("login.html")
    else:
        # parameterized username and password to prevent SQL injection
        res = cur.execute("SELECT id from users WHERE username = ? AND password = ?", [request.form["username"], request.form["password"]])
        user = res.fetchone()
        if user:
            token = secrets.token_hex()
            
            # parameterize username and token 
            cur.execute("INSERT INTO sessions (user, token) VALUES (?, ?);", [str(user[0]), token])
            con.commit()
            response = redirect("/home")
            response.set_cookie("session_token", token)
            return response
        else:
            return render_template("login.html", error="Invalid username and/or password!")

@app.route("/")
@app.route("/home")
def home():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        
        # parameterize session token
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          + "users.id = sessions.user WHERE sessions.token = ?;", [request.cookies.get("session_token")])
        user = res.fetchone()
        if user:
            # Generate CSRF Token
            csrf_token = secrets.token_urlsafe(16)

            res = cur.execute("SELECT message FROM posts WHERE user ='" + str(user[0]) + "';")
            posts = res.fetchall()

            resp = make_response(render_template("home.html", username=user[1], posts=posts, csrf_token=csrf_token))
            resp.set_cookie("csrf_token", csrf_token, httponly=True)
            return resp

    return redirect("/login")


@app.route("/posts", methods=["POST"])
@limiter.limit("2/second")
def posts():
    cur = con.cursor()
    if request.cookies.get("session_token") and request.form.get("csrf_token") == request.cookies.get("csrf_token"):
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          + "users.id = sessions.user WHERE sessions.token = ?;", [request.cookies.get("session_token")])
        user = res.fetchone()
        if user:
            cur.execute("INSERT INTO posts (message, user) VALUES (?,?);", [sanitize(request.form["message"]), str(user[0])])
            con.commit()
            return redirect("/home")

    return redirect("/login")


@app.route("/logout", methods=["GET"])
def logout():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          + "users.id = sessions.user WHERE sessions.token = ?", [request.cookies.get("session_token")])
        user = res.fetchone()
        if user:
            cur.execute("DELETE FROM sessions WHERE user = ?;", [str(user[0])])
            con.commit()

    response = redirect("/login")
    response.set_cookie("session_token", "", expires=0)

    return response
