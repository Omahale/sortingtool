from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import pandas as pd
from fuzzywuzzy import process
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///instance/database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Class model
class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    roll_call_file = db.Column(db.String(200))  # Path to uploaded roll call list

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/signup", methods=["POST"])
def signup():
    email = request.form["email"]
    password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
    
    if User.query.filter_by(email=email).first():
        flash("Email already exists!", "danger")
        return redirect(url_for("home"))

    new_user = User(email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    flash("Account created! Please log in.", "success")
    return redirect(url_for("home"))

@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]
    user = User.query.filter_by(email=email).first()
    
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid credentials!", "danger")

    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    return render_template("dashboard.html", classes=classes)

@app.route("/create_class", methods=["POST"])
@login_required
def create_class():
    class_name = request.form["class_name"]
    new_class = Class(name=class_name, teacher_id=current_user.id)
    db.session.add(new_class)
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/upload_rollcall/<int:class_id>", methods=["POST"])
@login_required
def upload_rollcall(class_id):
    file = request.files["roll_call"]
    if file:
        filepath = f"uploads/rollcall_{class_id}.csv"
        file.save(filepath)
        class_entry = Class.query.get(class_id)
        class_entry.roll_call_file = filepath
        db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
