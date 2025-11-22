import flask as fl
import sys
from flask_sqlalchemy import SQLAlchemy
import pyodbc
import re
import os
import bcrypt
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from datetime import datetime, timedelta
from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()  # Încarcă variabilele de mediu din .env

# --- INIȚIALIZARE ȘI CONFIGURARE APLICAȚIE ---

app = fl.Flask(__name__)

oauth = OAuth(app)


# Permitem conexiuni HTTP nesecurizate pentru lucrul local
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Cheia secretă pentru securitatea sesiunilor
app.secret_key = "o_cheie_fixa_si_puternica"

# CONFIG GOOGLE (Datele mele de acreditare)


# CONFIG SESIUNE SERVER-SIDE (Folosesc FileSystem pentru stabilitate)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_FILE_DIR"] = "./flask_session"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_DOMAIN"] = None

# Inițializăm gestiunea sesiunilor
Session(app)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mssql+pyodbc:///?odbc_connect=DRIVER={ODBC+Driver+17+for+SQL+Server};SERVER=VASIVBM\\SQLEXPRESS;DATABASE=CabinetVeterinar;Trusted_Connection=yes;"
)

db = SQLAlchemy(app)


# =======================================================
# --- LOGICA 1: ÎNREGISTRARE UTILIZATOR NOU ---
# =======================================================


@app.route("/register", methods=["POST"])
def register_user():
    username = fl.request.form.get("username")
    email = fl.request.form.get("email")
    password = fl.request.form.get("password")
    retypepassword = fl.request.form.get("retype_password")

    # 1. Validare inițială a câmpurilor
    if not username or not email or not password or password != retypepassword:
        return (
            "ERROR: Te rog completează toate câmpurile "
            "și asigură-te că parolele se potrivesc.",
            400,
        )

    # 2. Verificarea complexității parolei
    if len(password) < 8:
        return "ERROR: Parola trebuie să aibă minim 8 caractere.", 400

    special_chars = r'[!@#$%^&*(),.?":{}|<>]'
    if not re.search(special_chars, password):
        return (
            "ERROR: Parola trebuie să conțină " "cel puțin un caracter special.",
            400,
        )

    if not any(char.isalpha() for char in password):
        return "ERROR: Parola trebuie să conțină cel puțin o literă.", 400

    if not any(char.isdigit() for char in password):
        return "ERROR: Parola trebuie să conțină cel puțin o cifră", 400

    # 3. Validare strictă a domeniului Email-ului
    valid_domains = ("@yahoo.com", "@gmail.com")
    if not email.lower().endswith(valid_domains):
        return (
            "ERROR: Adresa de email trebuie să fie " "de pe Yahoo sau Gmail.",
            400,
        )

    try:
        # 4. Verific unicitatea Username-ului și a Email-ului în BD
        sql_check = """
        SELECT Username, Email FROM USER_ACCOUNT 
        WHERE Username = :user OR Email = :email
    """
        rezultat = db.session.execute(
            text(sql_check), {"user": username, "email": email}
        ).fetchone()

        if rezultat:
            return (
                "ERROR: Numele de utilizator sau email-ul "
                "există deja în baza de date.",
                409,
            )

        # Hashuiesc parola cu bcrypt
        password_bytes = password.encode("utf-8")
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        # 5. Inserare în baza de date
        sql_insert = """
        INSERT INTO USER_ACCOUNT (Username, Email, Parola) 
        VALUES (:user, :email, :password)
    """
        db.session.execute(
            text(sql_insert),
            {"user": username, "email": email, "password": hashed_password},
        )
        db.session.commit()

        # Redirecționez la pagina de login după ce înregistrarea a reușit
        return fl.redirect(fl.url_for("show_login_page"))

    except pyodbc.Error as ex:
        print(f"Eroare BD la înregistrare: {ex}", file=sys.stderr)
        return "Eroare de server la înregistrare.", 500


# =======================================================
# --- LOGICA 2: AUTENTIFICARE ȘI REMEMBER ME ---
# =======================================================


@app.route("/login", methods=["POST"])
def login_user():
    email = fl.request.form.get("email")
    password = fl.request.form.get("password")
    remember_me = fl.request.form.get("remember_me")

    if not email or not password:
        return "ERROR: Introduceti toate campurile.", 400

    try:
        sql_select = """
        SELECT Parola, Username FROM USER_ACCOUNT WHERE Email = :email
    """
        user_record = db.session.execute(text(sql_select), {"email": email}).fetchone()
        if not user_record:
            return "ERROR: Email sau parola incorecta.", 401

        stored_hashed_password = user_record[0]
        username = user_record[1]

        # Conversia hash-ului în bytes pentru verificarea cu bcrypt
        stored_hashed_password_bytes = stored_hashed_password.encode("utf-8")

        # 2. Verific parola cu BCRYPT
        if bcrypt.checkpw(password.encode("utf-8"), stored_hashed_password_bytes):

            # --- PAROLA ESTE CORECTĂ ---

            # Setăm variabilele de Sesiune Flask
            fl.session["logged_in"] = True
            fl.session["email"] = email
            fl.session["username"] = username

            # Creăm obiectul de Răspuns și Redirecționăm
            response = fl.make_response(fl.redirect(fl.url_for("index")))

            # LOGICA "REMEMBER ME" (Cookie-uri)
            if remember_me:
                expires_date = datetime.now() + timedelta(days=30)
                # Setăm cookie-ul pe obiectul de răspuns
                response.set_cookie(
                    "remember_email", email, expires=expires_date, httponly=True
                )
            else:
                response.delete_cookie("remember_email")

            return response

        else:
            # Parola incorectă
            return "ERROR: Email sau parola incorecta.", 401

    except pyodbc.Error as ex:
        print(f"Eroare BD la login: {ex}", file=sys.stderr)
        return "BD error: Eroare server la autentificare.", 500


# =======================================================
# --- LOGICA 3: RESETARE PAROLĂ ---
# =======================================================


@app.route("/forgot-passwordpage", methods=["POST"])
def forgot_password():
    email = fl.request.form.get("email")

    if not email:
        return ("ERROR: Te rog completează adresa de email.", 400)

    try:
        sql_check_email = """
        SELECT Email FROM USER_ACCOUNT WHERE Email = :email
    """
        user_record = db.session.execute(text(sql_check_email), {"email": email}).fetchone()
        if user_record:
            # Salvăm email-ul în sesiune pentru pasul următor (retype)
            fl.session["reset_email"] = email
            return fl.redirect(fl.url_for("show_retype_password_page"))
        else:
            return ("ERROR: Email-ul nu a fost găsit în baza de date.", 409)
    except pyodbc.Error as ex:
        print(f"Eroare BD la forgot password: {ex}", file=sys.stderr)
        return "Eroare server la verificarea email-ului.", 500


@app.route("/retype-password", methods=["POST"])
def retype_password():
    # Preluăm email-ul din sesiune
    email_to_update = fl.session.get("reset_email")

    password = fl.request.form.get("password")
    retype_password = fl.request.form.get("retype_password")

    # Validare
    if not email_to_update:
        return ("ERROR: Sesiunea de resetare a expirat. " "Te rog reia procedura.", 403)

    if not password or not retype_password or password != retype_password:
        return (
            "ERROR: Te rog completează ambele câmpuri "
            "și asigură-te că parolele se potrivesc.",
            400,
        )

    try:
        # Hashuim noua parolă
        password_bytes = password.encode("utf-8")
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        sql_update = """
        UPDATE USER_ACCOUNT SET Parola = :password WHERE Email = :email
    """
        result = db.session.execute(
            text(sql_update), {"password": hashed_password, "email": email_to_update}
        )
        db.session.commit()

        # Verificăm dacă s-a modificat un rând
        if result.rowcount > 0:
            db.session.commit()  # Echivalentul lui conexiune.commit()
            fl.session.pop("reset_email", None)  # Rămâne la fel
            return fl.redirect(fl.url_for("show_login_page"))
        else:
            # Nu mai trebuie apelat conexiune.close() sau db.session.close().
            # În acest caz, cel mai bine este să anulezi tranzacția dacă commit-ul nu a avut loc.
            db.session.rollback()  # Anulează orice schimbare ne-commit-ată
            return (
                "ERROR: Nu s-a putut actualiza parola. Email-ul nu a fost găsit.",
                404,
            )

    except pyodbc.Error as ex:
        print(f"Eroare BD la resetare parolă: {ex}", file=sys.stderr)
        return "Eroare server la resetarea parolei.", 500


# =======================================================
# --- LOGICA 4: GOOGLE OAUTH ȘI LOGOUT ---
# =======================================================


@app.route("/logout")
def logout():
    fl.session.clear()
    return fl.redirect("/")


@app.route("/login/google")
def login_google():
    redirect_uri = fl.url_for("authorize", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/google/callback")
def authorize():
    # Logica funcțională identică celei anterioare.
    try:
        token = oauth.google.authorize_access_token()
        userinfo = oauth.google.parse_id_token(token)

        google_email = userinfo["email"]
        google_name = userinfo.get("name", google_email.split("@")[0])

        # --- LOGICA TA DE BAZĂ DE DATE ---
        try:
            sql_check = """
            SELECT Username FROM USER_ACCOUNT WHERE Email = ?
            """
            existing_user = db.session.execute(text(sql_check), (google_email,)).fetchone()

            if not existing_user:
                # Register Logic (creăm username unic)
                username_base = google_name.replace(" ", "_").lower()
                username = username_base
                counter = 0
                while True:
                    db.session.execute(
                        text("SELECT Username FROM USER_ACCOUNT WHERE Username = ?"),
                        (username,),
                    )
                    if not db.session.fetchone():
                        break
                    counter += 1
                    username = f"{username_base}_{counter}"

                db.session.execute(
                    text("INSERT INTO USER_ACCOUNT (Username, Email, Parola) VALUES (?, ?, ?)"),
                    (username, google_email, "GOOGLE_AUTH_USER"),
                )
                db.session.commit()

        except pyodbc.Error as db_err:
            print(f"EROARE BD în OAuth: {db_err}")
            return f"Eroare Baza de Date: {db_err}", 500

        # Succes
        fl.session["user_email"] = google_email
        return fl.redirect(fl.url_for("index"))

    except Exception as e:
        print(f"EROARE FATALA OAuth: {e}")
        return f"Eroare Autentificare: {e}", 500


# =======================================================
# --- LOGICA 5: AFIȘARE PAGINI (Rute GET) ---
# =======================================================


@app.route("/")
def index():
    if "logged_in" not in fl.session or not fl.session["logged_in"]:
        return fl.redirect(fl.url_for("show_login_page"))

    sql_animale = "SELECT COUNT(Id_Animal) FROM ANIMAL"
    sql_stapani = "SELECT COUNT(Id_stapan) FROM STAPAN;"

    sql_examinari = "SELECT COUNT(Id_examinari) FROM EXAMINARI;"
    sql_luna = """
    SELECT COUNT(Id_interventii_chirurgicale)
    FROM INTERVENTII_CHIRURGICALE
    WHERE MONTH(Data) = MONTH(GETDATE()) AND YEAR(Data) = YEAR(GETDATE());
    """

    card_animale = db.session.execute(text(sql_animale)).scalar()
    card_stapani = db.session.execute(text(sql_stapani)).scalar()
    card_luna = db.session.execute(text(sql_luna)).scalar()
    card_examinari = db.session.execute(text(sql_examinari)).scalar()

    sql_alergii = """
        SELECT 
            COUNT(T3.Id_Alergie) AS Numar_Alergii 
        FROM ISTORIC_MEDICAL T1
        JOIN FISA_MEDICALA T2 ON T1.Id_istoricmedical = T2.Id_istoricmedical
        JOIN ALERGII T3 ON T2.Id_Alergie = T3.Id_Alergie
        WHERE YEAR(T1.Data_vizite) = YEAR(GETDATE()) 
        GROUP BY MONTH(T1.Data_vizite)
        ORDER BY MONTH(T1.Data_vizite);
    """
    # Rezultatul este o listă de tupluri/obiecte
    rezultat_alergii = db.session.execute(text(sql_alergii)).fetchall()

    # Convertim rezultatul într-un format ușor de folosit în JavaScript:
    alergii_data = [
        row[0] for row in rezultat_alergii
    ]  # Extragem doar coloana cu numărul alergiilor

    pie_data = [card_examinari, card_luna, card_animale]

    # 2. PREIA DATELE DIN SESIUNE
    DEFAULT_AVATAR = fl.url_for("static", filename="img/default_avatar.jpg")

    user_data = {
        "username": fl.session.get("username", "Utilizator Necunoscut"),
        "profile_picture_url": fl.session.get(
            "profile_pic", DEFAULT_AVATAR
        ),  # Cale implicită
    }
    return fl.render_template(
        "dashboard.html",
        user=user_data,
        # ... alte variabile
        nr_animale=card_animale,
        nr_stapani=card_stapani,
        nr_interventii=card_luna,  # Reutilizăm variabila din 'Intervenții Luna Asta'
        nr_examinari=card_examinari,
        alergii_data=alergii_data,
        pie_data=pie_data
    )


@app.route("/login")
def show_login_page():
    # Citim cookie-ul pentru Remember Me
    remembered_email = fl.request.cookies.get("remember_email")

    return fl.render_template("login.html", remembered_email=remembered_email)


@app.route("/register")
def register():
    return fl.render_template("register.html")


@app.route("/forgot-password")
def show_forgot_password_page():
    return fl.render_template("forgot-password.html")


@app.route("/retype-password")
def show_retype_password_page():
    return fl.render_template("retype_password.html")


# --- Rute nefolosite (comentate) ---
# @app.route("/save-programare", methods=["POST"])
# ...
# @app.route("/save-programare")
# ...


if __name__ == "__main__":
    app.run(debug=True)
