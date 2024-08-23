import os
import secrets
from urllib.parse import urlencode
import requests
import json
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
import requests
from flask import Flask, render_template, request
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    redirect,
    url_for,
    render_template,
    flash,
    session,
    current_app,
    request,
    abort,
)
from apscheduler.schedulers.background import BackgroundScheduler
from flask_mail import Mail, Message


load_dotenv()

key = os.environ.get("CHAT_ENCRYPTION_KEY")
if key is None:
    key = Fernet.generate_key()
    # Store the key securely, e.g., in an environment variable
cipher_suite = Fernet(key)

app = Flask(__name__)
app.config["SECRET_KEY"] = "top secret!"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["MAIL_USERNAME"] = "Hari"
app.config["OAUTH2_PROVIDERS"] = {
    # Google OAuth 2.0 documentation:
    # https://developers.google.com/identity/protocols/oauth2/web-server#httprest
    "google": {
        "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
        "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
        "authorize_url": "https://accounts.google.com/o/oauth2/auth",
        "token_url": "https://accounts.google.com/o/oauth2/token",
        "userinfo": {
            "url": "https://www.googleapis.com/oauth2/v3/userinfo",
            "email": lambda json: json["email"],
        },
        "scopes": ["https://www.googleapis.com/auth/userinfo.email"],
    },
    # GitHub OAuth 2.0 documentation:
    # https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
    "github": {
        "client_id": os.environ.get("GITHUB_CLIENT_ID"),
        "client_secret": os.environ.get("GITHUB_CLIENT_SECRET"),
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo": {
            "url": "https://api.github.com/user/emails",
            "email": lambda json: json[0]["email"],
        },
        "scopes": ["user:email"],
    },
}
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),  # Your email
    MAIL_PASSWORD=os.environ.get(
        "MAIL_PASSWORD"
    ),  # Your email password or app-specific password
)

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = "index"
mail = Mail(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=True)


class ChatLog(db.Model):
    __tablename__ = "chat_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    encrypted_message = db.Column(db.LargeBinary, nullable=False)

    user = db.relationship("User", back_populates="chat_logs")


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/index")
@login_required
def index():
    return render_template("index.html")


@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("login"))


@app.route("/authorize/<provider>")
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        # return redirect(url_for("index"))
        return redirect(url_for("index"))

    provider_data = current_app.config["OAUTH2_PROVIDERS"].get(provider)
    if provider_data is None:
        abort(404)

    # generate a random string for the state parameter
    session["oauth2_state"] = secrets.token_urlsafe(16)

    # create a query string with all the OAuth2 parameters
    qs = urlencode(
        {
            "client_id": provider_data["client_id"],
            "redirect_uri": url_for(
                "oauth2_callback", provider=provider, _external=True
            ),
            "response_type": "code",
            "scope": " ".join(provider_data["scopes"]),
            "state": session["oauth2_state"],
        }
    )

    # redirect the user to the OAuth2 provider authorization URL
    return redirect(provider_data["authorize_url"] + "?" + qs)


@app.route("/callback/<provider>")
def oauth2_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for("index"))

    provider_data = current_app.config["OAUTH2_PROVIDERS"].get(provider)
    if provider_data is None:
        abort(404)

    # if there was an authentication error, flash the error messages and exit
    if "error" in request.args:
        for k, v in request.args.items():
            if k.startswith("error"):
                flash(f"{k}: {v}")
        return redirect(url_for("index"))

    # make sure that the state parameter matches the one we created in the
    # authorization request
    if request.args["state"] != session.get("oauth2_state"):
        abort(401)

    # make sure that the authorization code is present
    if "code" not in request.args:
        abort(401)

    # exchange the authorization code for an access token
    response = requests.post(
        provider_data["token_url"],
        data={
            "client_id": provider_data["client_id"],
            "client_secret": provider_data["client_secret"],
            "code": request.args["code"],
            "grant_type": "authorization_code",
            "redirect_uri": url_for(
                "oauth2_callback", provider=provider, _external=True
            ),
        },
        headers={"Accept": "application/json"},
    )
    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get("access_token")
    if not oauth2_token:
        abort(401)

    # use the access token to get the user's email address
    response = requests.get(
        provider_data["userinfo"]["url"],
        headers={
            "Authorization": "Bearer " + oauth2_token,
            "Accept": "application/json",
        },
    )
    if response.status_code != 200:
        abort(401)
    email = provider_data["userinfo"]["email"](response.json())

    # find or create the user in the database
    user = db.session.scalar(db.select(User).where(User.email == email))
    if user is None:
        user = User(email=email, username=email.split("@")[0])
        db.session.add(user)
        db.session.commit()

    # log the user in
    login_user(user)
    return redirect(url_for("index"))


def get_completion(prompt):
    url = "http://localhost:11434/api/generate"
    headers = {"Content-Type": "application/json"}
    data = {
        "model": "qwen2:0.5b",
        "prompt": prompt,
        "stream": False,
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))

    return json.loads(response.text)["response"]


def encrypt_message(message):
    encrypted_message = cipher_suite.encrypt(message.encode())
    print(f"Original Message: {message}")
    print(f"Encrypted Message: {encrypted_message}")
    return encrypted_message


def decrypt_message(encrypted_message):
    try:
        decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
        print(f"Decrypted Message: {decrypted_message}")
        return decrypted_message
    except InvalidToken as e:
        print(f"Decryption failed for message: {encrypted_message}")
        print(f"Error: {e}")
        return None


@app.route("/chatlogs", methods=["GET"])
@login_required
def get_chat_logs():
    logs = ChatLog.query.filter_by(user_id=current_user.id).all()
    return render_template(
        "chat_logs.html", logs=[decrypt_message(log.encrypted_message) for log in logs]
    )


@app.route("/chatlogs/delete", methods=["POST"])
@login_required
def delete_chat_logs():
    ChatLog.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash("Your chat logs have been deleted.")
    return redirect(url_for("index"))


@app.route("/")
def home():
    return render_template("index.html")


def send_chat_logs():
    with app.app_context():
        users = User.query.all()
        for user in users:
            logs = ChatLog.query.filter_by(user_id=user.id).all()
            if logs:
                decrypted_logs = [
                    decrypt_message(log.encrypted_message) for log in logs
                ]
                chat_log_content = "\n".join(decrypted_logs)

                msg = Message(
                    subject="Weekly Chat Logs",
                    recipients=[user.email],
                    body=f"Dear {user.username},\n\nHere are your chat logs for the past week:\n\n{chat_log_content}",
                    sender=app.config[
                        "MAIL_USERNAME"
                    ],  # Ensure the sender is specified here
                )
                mail.send(msg)
                print("Mailed: ", decrypted_logs)


# Routes for chat logging and retrieval
@app.route("/get")
def get_bot_response():
    userText = request.args.get("msg")
    response = get_completion(userText)

    # Store the encrypted chat log
    if current_user.is_authenticated:
        encrypted_message = encrypt_message(userText)
        chat_log = ChatLog(
            user_id=current_user.id,
            message=userText,
            encrypted_message=encrypted_message,
        )
        db.session.add(chat_log)
        db.session.commit()

    return response


with app.app_context():
    db.create_all()

User.chat_logs = db.relationship(
    "ChatLog", order_by=ChatLog.timestamp, back_populates="user"
)

# Schedule the task to run weekly
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=send_chat_logs, trigger="interval", weeks=9.920634920634921e-5 * 10
)
scheduler.start()

if __name__ == "__main__":
    app.run(debug=True)
