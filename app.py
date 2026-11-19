from flask import Flask, render_template, session, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from PIL  import Image, UnidentifiedImageError
import dotenv
import secrets
import os
import ssl
import smtplib
from email.message import EmailMessage

dotenv.load_dotenv(override=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

db = SQLAlchemy(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  
)

oauth = OAuth(app)


google = oauth.register(
    name="google",

    client_id=os.environ["CLIENT_ID"],

    client_secret=os.environ["CLIENT_SECRET"],

    server_metadata_url=(
        "https://accounts.google.com/.well-known/openid-configuration"
    ),

    client_kwargs={
        "scope": "openid email profile"
    }
)



def db_init():
    with app.app_context():
        query = text("""
               CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name VARCHAR(100) NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password VARCHAR(255),

                google_id VARCHAR(255) UNIQUE,

                is_verified INTEGER NOT NULL DEFAULT 0,
                verification_code_hash TEXT,
                verification_sent_at INTEGER,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                profile_image VARCHAR(255)
                );
                """)
        db.session.execute(query)
        db.session.commit()
        


# function to generate OTP
def generate_verification_code():
    return str(secrets.randbelow(900000) + 100000)



# function for email sender
def send_verification_email(receiver_email, verification_code):
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")

    if not sender_email or not sender_password:
        raise ValueError("Email credentials are missing from .env")

    message = EmailMessage()

    message["Subject"] = "Verify Your Email Address"
    message["From"] = sender_email
    message["To"] = receiver_email

    message.set_content(
        f"""
Hello,

Thank you for registering with us.

Your email verification code is:

{verification_code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Regards,
Authentication Team
        """
    )
    
    html_content = f"""
    
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
</head>

<body style="
    margin: 0;
    padding: 30px 15px;
    background-color: #0b1120;
    font-family: Arial, Helvetica, sans-serif;
">

    <table width="100%" cellpadding="0" cellspacing="0"
           style="max-width: 560px; margin: auto;">

        <!-- Header -->
        <tr>
            <td style="
                background-color: #0b1120;
                padding: 25px 20px;
                text-align: center;
            ">
                <h2 style="
                    color: #f8fafc;
                    margin: 0;
                    font-size: 22px;
                    letter-spacing: 2px;
                ">
                    <span style="color: #22d3ee;">◆</span>
                    AUTHENTICATION
                </h2>

                <p style="
                    color: #94a3b8;
                    font-size: 11px;
                    letter-spacing: 2px;
                    margin-bottom: 0;
                ">
                    ACCOUNT SECURITY
                </p>
            </td>
        </tr>

        <!-- Main Content -->
        <tr>
            <td style="
                background-color: #111c30;
                padding: 35px 25px;
                border-radius: 12px;
            ">

                <h1 style="
                    color: #f8fafc;
                    text-align: center;
                    font-size: 26px;
                    margin-top: 0;
                ">
                    Verify Your Email
                </h1>

                <p style="
                    color: #94a3b8;
                    font-size: 15px;
                    line-height: 1.7;
                    text-align: center;
                ">
                    Thank you for registering with us!
                    We're excited to have you on board.
                </p>

                <p style="
                    color: #cbd5e1;
                    font-size: 14px;
                    text-align: center;
                    line-height: 1.6;
                ">
                    Use the verification code below
                    to complete your registration.
                </p>

                <!-- OTP Box -->
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="
                            background-color: #17243b;
                            border: 1px solid #22d3ee;
                            border-radius: 10px;
                            padding: 25px 15px;
                            text-align: center;
                        ">

                            <p style="
                                color: #94a3b8;
                                font-size: 12px;
                                letter-spacing: 2px;
                                margin-top: 0;
                            ">
                                YOUR VERIFICATION CODE
                            </p>

                            <h1 style="
                                color: #22d3ee;
                                font-size: 34px;
                                letter-spacing: 9px;
                                margin: 15px 0;
                            ">
                                { verification_code }
                            </h1>

                            <p style="
                                color: #94a3b8;
                                font-size: 12px;
                                margin-bottom: 0;
                            ">
                                Enter this code on the verification page.
                            </p>

                        </td>
                    </tr>
                </table>

                <p style="
                    color: #22d3ee;
                    text-align: center;
                    font-size: 14px;
                    margin-top: 25px;
                ">
                    ⏱ This code expires in 10 minutes.
                </p>

                <hr style="
                    border: none;
                    border-top: 1px solid #263750;
                    margin: 25px 0;
                ">

                <p style="
                    color: #94a3b8;
                    font-size: 13px;
                    line-height: 1.7;
                ">
                    If you didn't create an account or request
                    this code, you can safely ignore this email.
                </p>

                <p style="
                    color: #f8fafc;
                    font-size: 14px;
                    line-height: 1.8;
                ">
                    Regards,<br>
                    <strong style="color: #22d3ee;">
                        Authentication Team
                    </strong>
                </p>

            </td>
        </tr>

        <!-- Footer -->
        <tr>
            <td style="
                text-align: center;
                padding: 22px 10px;
            ">
                <p style="
                    color: #64748b;
                    font-size: 11px;
                    line-height: 1.7;
                ">
                    © 2026 Authentication System.
                    All rights reserved.<br>
                    This is an automated email.
                    Please do not reply.
                </p>
            </td>
        </tr>

    </table>

</body>
</html>

    """
    message.add_alternative(html_content, subtype="html")
    context = ssl.create_default_context()
    
    with smtplib.SMTP("smtp.gmail.com", 587) as server:

        server.ehlo()

        server.starttls(context=context)

        server.ehlo()

        server.login(sender_email, sender_password)

        try:
            server.send_message(message)
        except:
            return False
        
        return True


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    else:
        return redirect(url_for("home"))
    

@app.route("/home")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    else:
        return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))
    else:
        if request.method=="POST":
            email = request.form.get("email").strip()
            password = request.form.get("password").strip()      
            query = text("SELECT * FROM users WHERE email = :email")
            data = db.session.execute(query, {"email":email}).fetchone()
            if data is None:
                flash("This email is not registed", "error")
                return redirect(url_for("login"))
            elif data and data.is_verified==0:
                flash("Verify your email", "warning")
                return redirect(url_for("register"))
            else:
                if check_password_hash(data.password, password):
                    session.clear()
                    session["user_id"] = data.id
                    session["name"] = data.name
                    return redirect(url_for("home"))
                else:
                    flash("Incorrect password", "error")
                    return redirect(url_for("login"))                       
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" not in session:
        if request.method=="POST":
            name = request.form.get("name").strip()
            email = request.form.get("email").strip().lower()
            password = request.form.get("password").strip()
            confirm_password = request.form.get("confirm_password").strip()
            if password==confirm_password:
                try:
                    data = db.session.execute(text("SELECT * FROM users WHERE email = :email"), {"email":email}).fetchone()
                    if data is None:
                        code = generate_verification_code()
                        if send_verification_email(email, code):
                            query = text("""INSERT INTO users(name, email, password, verification_code_hash) VALUES(:name, :email, :password, :verification_code_hash)""")
                            db.session.execute(query, {
                                "name":name,
                                "email":email,
                                "password":generate_password_hash(password),
                                "verification_code_hash":generate_password_hash(code)
                            })
                            db.session.commit()
                            query = text("SELECT * FROM users WHERE email = :email")
                            data = db.session.execute(query, {"email":email}).fetchone()
                            session.clear()
                            session["verified_pending_id"] = data.id
                            return redirect(url_for("verify_email"))
                        else:
                            flash("Please enter correct gmail", "error")
                            return redirect(url_for("register"))
                    else:
                        raise IntegrityError(None, None, Exception("Duplicate entry"))         
                except IntegrityError:
                    query = text("SELECT * FROM users WHERE email = :email")
                    result = db.session.execute(query, {"email":email}).fetchone()
                    if result and result.is_verified==0:
                        code = generate_verification_code()
                        query = text("UPDATE users SET verification_code_hash = :verification_code_hash, name = :name, password = :password WHERE email = :email")
                        db.session.execute(query, {"verification_code_hash":generate_password_hash(code), "name":name, "password":generate_password_hash(password), "email":email})
                        db.session.commit()
                        if send_verification_email(email, code):
                            session["verified_pending_id"] = data.id
                            return redirect(url_for("verify_email"))
                        else:
                            flash("Email does not sent, Please try again", "error")
                            return redirect(url_for("register"))
                    else:
                        flash("This email already exist", "error")
                        db.session.rollback()
                        return redirect(url_for("register"))              
            else:
                flash("Confirm password does not match with password", "error")
            
            return redirect(url_for("register"))
    else:
        return redirect(url_for("home"))
    return render_template("register.html")


@app.route("/verify_email", methods=["GET", "POST"])
def verify_email():
    if "verified_pending_id" in session:    
        if request.method=="POST":
            code = request.form.get("verification_code")
            data = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id":session.get("verified_pending_id")}).fetchone()
            is_valid = check_password_hash(data.verification_code_hash, str(code))
            if is_valid:
                query = text("UPDATE users SET is_verified = :is_verified WHERE id = :id")
                db.session.execute(query, {"is_verified":1, "id":session.get("verified_pending_id")})
                db.session.commit()
                user_id = session.get("verified_pending_id")
                session.clear()
                session["user_id"] = user_id
                session["name"] = data.name
                return redirect(url_for("home"))
            else:
                session.clear()
                flash("Verification code is incorrect", "error")
                return redirect(url_for("register"))
    elif "user_id" in session:
        return redirect(url_for("home"))
    return render_template("verify_email.html")


@app.route("/google-login")
def google_login():

    if "user_id" in session:
        return redirect(url_for("home"))
    try:

        redirect_uri = url_for(
            "google_callback",
            _external=True
        )
        return google.authorize_redirect(redirect_uri)

    except Exception:
        app.logger.exception("Google login initialization failed")

        flash(
            "Unable to connect to Google. Please try again.",
            "error"
        )
        return redirect(url_for("login"))
    

@app.route("/logout", methods=["GET", "POST"])
def logout():
    if "user_id" in session:
        session.clear()
        return redirect(url_for("login"))
    else:
        return redirect(url_for("login"))
 

@app.route("/google-callback")
def google_callback():
    if request.args.get("error"):
        flash(
            "Google authentication was cancelled or failed.",
            "error"
        )
        return redirect(url_for("login"))

    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo")

        if not user_info:
            flash(
                "Unable to retrieve your Google account information.",
                "error"
            )
            return redirect(url_for("login"))
        google_id = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name")

        email_verified = user_info.get("email_verified")

        if not google_id or not email or not name:
            flash(
                "Google did not provide the required account information.",
                "error"
            )
            return redirect(url_for("login"))

        if email_verified is not True:
            flash(
                "Please use a verified Google email address.",
                "error"
            )
            return redirect(url_for("login"))
        
        email = email.strip().lower()

        query = text("""
            SELECT *
            FROM users
            WHERE google_id = :google_id
        """)

        user = db.session.execute(
            query,
            {"google_id": google_id}
        ).fetchone()

        if user:
            user_id = user.id
            user_name = user.name

        else:
            email_query = text("""
                SELECT id
                FROM users
                WHERE email = :email
            """)

            existing_user = db.session.execute(
                email_query,
                {"email": email}
            ).fetchone()

            if existing_user:

                flash(
                    "An account with this email already exists. "
                    "Please log in using your password first.",
                    "warning"
                )

                return redirect(url_for("login"))
            insert_query = text("""
                INSERT INTO users (
                    name,
                    email,
                    password,
                    google_id,
                    is_verified
                )
                VALUES (
                    :name,
                    :email,
                    NULL,
                    :google_id,
                    :is_verified
                )
            """)

            try:
                result = db.session.execute(
                    insert_query,
                    {
                        "name": name,
                        "email": email,
                        "google_id": google_id,
                        "is_verified":1
                    }
                )

                db.session.commit()

                user_id = result.lastrowid
                user_name = name

            except IntegrityError:
                db.session.rollback()

                user = db.session.execute(
                    query,
                    {"google_id": google_id}
                ).fetchone()

                if user is None:
                    app.logger.exception(
                        "Google account database conflict"
                    )
                    flash(
                        "Unable to create your account. Please try again.",
                        "error"
                    )
                    return redirect(url_for("login"))

                user_id = user.id
                user_name = user.name

        session.clear()

        session["user_id"] = user_id
        session["name"] = user_name

        flash(
            "You have successfully logged in with Google!",
            "success"
        )
        return redirect(url_for("home"))

    except Exception:
        db.session.rollback()

        app.logger.exception(
            "Google authentication callback failed"
        )

        flash(
            "Something went wrong during Google login. "
            "Please try again.",
            "error"
        )
        return redirect(url_for("login"))
    
    
    


@app.route("/profile")
def profile():
    if "user_id" in session:
        user = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id":session.get("user_id")}).fetchone()
        return render_template("profile.html", user=user)
    else:
        return redirect(url_for("login"))




PROFILE_UPLOAD_FOLDER = os.path.join(
    app.root_path,
    "static",
    "uploads",
    "profiles"
)

ALLOWED_EXTENSIONS = ("jpg", "jpeg", "png", "webp")

@app.route("/upload_profile_image", methods=["POST"])
def upload_profile_image():
    if "user_id" not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))
    image = request.files.get("profile_image")
    name = request.form.get("username")
    user_id = session.get("user_id")
    
    db.session.execute(text("UPDATE users SET name = :name WHERE id = :id"), {"name":name, "id":user_id})
    db.session.commit()
    session["name"] = name
    
    if image is None or image.filename=="":
        flash("Image not uploaded", "error")
        return redirect(url_for("profile"))
    
    extension = image.filename.rsplit(".", 1)[-1].lower()
    
    if "." not in image.filename or extension not in ALLOWED_EXTENSIONS:
        flash("Only JPG, JPEG, PNG and WEBP images are allowed.", "error")
        return redirect(url_for("profile"))

    filename = secrets.token_hex(16) + "." + extension
    filepath = os.path.join(PROFILE_UPLOAD_FOLDER, filename)
    result = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id":user_id}).fetchone()
    if result and result.profile_image:
        try:
            os.remove(os.path.join(PROFILE_UPLOAD_FOLDER, result.profile_image))
            db.session.execute(text("UPDATE users SET profile_image = :profile_image WHERE id = :id"), {"profile_image":filename, "id":user_id})
            db.session.commit()
            image.save(filepath)
            flash("successfully image Changed", "success")
        except:
            db.session.rollback()
            flash("Please try again", "error")
            return redirect(url_for("profile"))
    else:
        try:
            db.session.execute(text("UPDATE users SET profile_image = :profile_image WHERE id = :id"), {"profile_image":filename, "id":user_id})
            db.session.commit()
            image.save(filepath)
            flash("successfully image added", "success")
        except:
            db.session.rollback()
            flash("Please try again", "error")
            return redirect(url_for("profile"))
    return redirect(url_for("profile"))
    

@app.route("/forget_password")
def forget_password():
    if "user_id" in session:
        return redirect(url_for("home"))
    else:
        return render_template("forget_password.html")


@app.route("/forget_password_verification", methods=["GET", "POST"])
def forget_password_verification():
    if "user_id" in session:
            return redirect(url_for("home"))
    else:
        if request.method=="POST":
            email = request.form.get("email")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")
            if password==confirm_password:
                query = text("SELECT * FROM users WHERE email = :email")
                result = db.session.execute(query, {"email":email}).fetchone()
                if result and result.is_verified==1:
                    code = generate_verification_code()
                    if send_verification_email(email, code):
                        query = text("""UPDATE users SET password = :password, verification_code_hash = :verification_code_hash WHERE email = :email;""")
                        db.session.execute(query, {
                            "password":generate_password_hash(password),
                            "verification_code_hash":generate_password_hash(code),
                            "email":email
                        })
                        db.session.commit()
                        query = text("SELECT * FROM users WHERE email = :email")
                        data = db.session.execute(query, {"email":email}).fetchone()
                        session.clear()
                        session["forget_pending_id"] = data.id
                        return redirect(url_for("verify_forget_email"))
                    else:
                        flash("Something went wrong, Please try again later ", "error")
                        return redirect(url_for("register"))
                else:
                    flash("This email is not registered, Please registered it", "error")
                    return redirect(url_for("register"))
            else:
                flash("The password does not match with confirm password")
                return redirect(url_for("forget_password_verification"))        
    return redirect(url_for("forget_password_verification"))
        
        

        
@app.route("/verify_forget_email", methods=["GET", "POST"])
def verify_forget_email():
    if "user_id" in session:
        return redirect(url_for("home"))
    
    elif "forget_pending_id" in session:
        if request.method=="POST":
            code = request.form.get("verification_code")
            data = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id":session.get("forget_pending_id")}).fetchone()
            is_valid = check_password_hash(data.verification_code_hash, str(code))
            if is_valid:
                user_id = session.get("forget_pending_id")
                session.clear()
                session["user_id"] = user_id
                session["name"] = data.name
                return redirect(url_for("home"))
            else:
                session.clear()
                flash("Verification code is incorrect", "error") 
                return redirect(url_for("forget_password"))     
    return render_template("verify_forget_email.html")
            




@app.route("/change_password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
    if new_password==confirm_password:
        result = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id":session.get("user_id")}).fetchone()
        if check_password_hash(result.password, current_password):
            password = generate_password_hash(new_password)
            try:
                db.session.execute(text("UPDATE users SET password = :password WHERE id = :id"), {"password":password, "id":session.get("user_id")})
                db.session.commit()
                flash("Successfully password changed", "success")
            except IntegrityError:
                db.session.rollback()
                flash("Please try again", "error")
                redirect(url_for("profile"))  
        else:
            flash("The current password is incorrect", "error")
            redirect(url_for("profile"))
    else:
        flash("New password does not match with confirm password", "error")
        return redirect(url_for("profile"))        
    return redirect(url_for("profile"))


if __name__ == "__main__":
    db_init()
    app.run(debug=True)