from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Fake user data (later we will move this to a database)
users = {
    "kennedy": {"password": "1234", "balance": 5000},
    "toby": {"password": "abcd", "balance": 3000}
}

@app.route("/")
def home():
    return "Welcome to Kennedy Banking Demo! <a href='/login'>Login here</a>"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in users and users[username]["password"] == password:
            return redirect(url_for("dashboard", user=username))
        else:
            return "Invalid credentials! <a href='/login'>Try again</a>"
    return render_template("login.html")

@app.route("/dashboard/<user>")
def dashboard(user):
    if user in users:
        balance = users[user]["balance"]
        return render_template("dashboard.html", user=user, balance=balance)
    return "User not found"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)