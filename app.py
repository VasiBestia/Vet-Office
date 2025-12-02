import flask as fl
import sys
from flask_sqlalchemy import SQLAlchemy
import pyodbc
import re
import os
import bcrypt
import time
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from datetime import datetime, timedelta
from dotenv import load_dotenv
from sqlalchemy import text
from werkzeug.utils import secure_filename

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
        # 1. SELECT Parola, Username, Id_user, Id_stapan (pentru verificarea setup-ului)
        sql_select = """
            SELECT Parola, Username, Id_user
            FROM USER_ACCOUNT
            WHERE Email = :email
        """
        user_record = db.session.execute(text(sql_select), {"email": email}).fetchone()

        if not user_record:
            return "ERROR: Email sau parola incorecta.", 401

        # Extragem datele din tuplu (ne așteptăm la 4 coloane acum)
        stored_hashed_password = user_record[0]
        username = user_record[1]
        user_id = user_record[2]

        # 2. Verific parola cu BCRYPT
        if not bcrypt.checkpw(
            password.encode("utf-8"), stored_hashed_password.encode("utf-8")
        ):
            return "ERROR: Email sau parola incorecta.", 401

        # --- PAROLA ESTE CORECTĂ ---

        # 3. SETARE SESIUNE FLASK
        fl.session["logged_in"] = True
        fl.session["user_id"] = user_id
        fl.session["username"] = username
        fl.session["email"] = email

        # 4. DETERMINARE RUTA DE REDIRECTIONARE
        response = fl.make_response(fl.redirect(fl.url_for("index")))
        # 6. LOGICA "REMEMBER ME" (Cookie-uri)
        if remember_me:
            expires_date = datetime.now() + timedelta(days=30)
            response.set_cookie(
                "remember_email", email, expires=expires_date, httponly=True
            )
        else:
            response.delete_cookie("remember_email")

        return response

    except Exception as e:
        # Loghează eroarea și returnează un mesaj de eroare generic
        print(f"Eroare la autentificare: {e}")
        return "ERROR: Eroare internă a serverului la autentificare.", 500


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
        user_record = db.session.execute(
            text(sql_check_email), {"email": email}
        ).fetchone()
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


# @app.route("/logout")
# def logout():
#     fl.session.clear()
#     return fl.redirect("/")


# @app.route("/login/google")
# def login_google():
#     redirect_uri = fl.url_for("authorize", _external=True)
#     return oauth.google.authorize_redirect(redirect_uri)


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
            existing_user = db.session.execute(
                text(sql_check), (google_email,)
            ).fetchone()

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
                    text(
                        "INSERT INTO USER_ACCOUNT (Username, Email, Parola) VALUES (?, ?, ?)"
                    ),
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
        pie_data=pie_data,
    )


@app.route("/login")
def show_login_page():
    # Citim cookie-ul pentru Remember Me
    remembered_email = fl.request.cookies.get("remember_email")

    return fl.render_template("login.html", remembered_email=remembered_email)


@app.route("/register")
def show_register_page():
    return fl.render_template("register.html")


@app.route("/forgot-password")
def show_forgot_password_page():
    return fl.render_template("forgot-password.html")


@app.route("/retype-password")
def show_retype_password_page():
    return fl.render_template("retype_password.html")


@app.route("/animal", methods=["GET", "POST"])
def show_animal_page():
    # 1. Verificare Autentificare
    if "user_id" not in fl.session:
        return fl.redirect(
            fl.url_for("show_login_page")
        )  # Asigură-te că numele rutei de login e corect

    user_id = fl.session["user_id"]

    setup_needed_animal = fl.session.get("setup_needed_animal", None)

    search_animal_id = fl.request.args.get("id", type=int)

    current_animal_id = None

    # --- LOGICA DE POST (Când apeși butonul "Salvează") ---
    if fl.request.method == "POST":
        try:
            nume = fl.request.form["nume"]
            specie = fl.request.form["specie"]
            rasa = fl.request.form["rasa"]
            varsta = fl.request.form["varsta"]
            sex = fl.request.form["sex"]

            # Inserăm în STAPAN
            sql_insert = "INSERT INTO ANIMAL (Nume, Specie, Rasa, Varsta, Sex) VALUES (:n, :s, :r, :v, :x)"
            db.session.execute(
                text(sql_insert),
                {"n": nume, "s": specie, "r": rasa, "v": varsta, "x": sex},
            )

            sql_select_new_id = """
            SELECT Id_animal FROM ANIMAL 
            WHERE Nume=:nume AND Specie=:specie AND Rasa=:rasa AND Varsta=:varsta AND Sex=:sex"""

            new_id = db.session.execute(
                text(sql_select_new_id),
                {
                    "nume": nume,
                    "specie": specie,
                    "rasa": rasa,
                    "varsta": varsta,
                    "sex": sex,
                },
            ).scalar()

            sql_check = """

        SELECT Id_user FROM FISA_MEDICALA

        WHERE Id_user = :user_id
          """
            rezultat = db.session.execute(
                text(sql_check), {"user_id": user_id}
            ).fetchone()

            if not rezultat:

                sql_insert_fisa = """

                INSERT INTO FISA_MEDICALA (Id_user) VALUES (:user_id)

                """

                db.session.execute(text(sql_insert_fisa), {"user_id": user_id})

                db.session.commit()

            # Luăm ID-ul nou creat

            # Legăm de User
            sql_link = "UPDATE FISA_MEDICALA SET Id_Animal = :sid WHERE Id_user = :uid"
            db.session.execute(text(sql_link), {"sid": new_id, "uid": user_id})

            fl.session["setup_needed_animal"] = False

            db.session.commit()
            fl.flash("Date salvate cu succes!", "success")

            # Refresh la pagina ca să vedem Cardurile
            return fl.redirect(fl.url_for("show_animal_page"))

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare: {e}", "danger")

        # --- LOGICA DE GET (Afișare Pagină) ---
    if search_animal_id is not None:
        # PRIORITATE 1: Dacă ID-ul vine din căutare, îl folosim direct
        current_animal_id = search_animal_id
    else:
        current_animal_id = db.session.execute(
            text("SELECT FM.Id_Animal FROM FISA_MEDICALA FM WHERE FM.Id_user = :uid"),
            {"uid": user_id},
        ).scalar()
    # 2. Verificăm dacă avem date legate de acest user
    # Facem JOIN direct intre USER_ACCOUNT si STAPAN
    if current_animal_id:
        fl.session["setup_needed_animal"] = False

        sql_get_data = """
                SELECT A.Nume, A.Specie, A.Rasa, A.Varsta, A.Sex
                FROM FISA_MEDICALA FM
                FULL JOIN ANIMAL A ON FM.Id_animal = A.Id_animal
                WHERE FM.Id_user = :uid
            """
        result = db.session.execute(text(sql_get_data), {"uid": user_id}).fetchone()

        # 3. Pregătim datele pentru Template
        user_data = {
            "username": fl.session.get("username", "User"),
            "profile_picture_url": fl.session.get(
                "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
            ),
        }

        # Daca avem rezultat, înseamnă că omul și-a completat datele -> setup_needed = False
    if result and result[0] is not None:
        # Obținem Id-ul animalului curent legat de user (dacă există)
        current_animal_id = db.session.execute(
            text("SELECT FM.Id_Animal FROM FISA_MEDICALA FM WHERE FM.Id_user = :uid"),
            {"uid": user_id},
        ).scalar()

        sql_medical_report = """
        SELECT 
            -- === 1. EXAMINARI (Doar Ultima Vizită) ===
            (
                SELECT TOP 1 E.Greutate 
                FROM FISA_MEDICALA FM 
                JOIN EXAMINARI E ON FM.Id_examinari = E.Id_examinari 
                WHERE FM.Id_Animal = :aid 
                ORDER BY FM.Id_fisa_medicala DESC
            ) AS Greutate_Examinare,

            (
                SELECT TOP 1 E.Temperatură 
                FROM FISA_MEDICALA FM 
                JOIN EXAMINARI E ON FM.Id_examinari = E.Id_examinari 
                WHERE FM.Id_Animal = :aid 
                ORDER BY FM.Id_fisa_medicala DESC
            ) AS Temperatură_Examinare,

            (
                SELECT TOP 1 E.Condiție_Corporală 
                FROM FISA_MEDICALA FM 
                JOIN EXAMINARI E ON FM.Id_examinari = E.Id_examinari 
                WHERE FM.Id_Animal = :aid 
                ORDER BY FM.Id_fisa_medicala DESC
            ) AS Condiție_Corporală_Examinare,

            -- === 2. ALERGII (Lista Unică) ===
            (
                SELECT STRING_AGG(Tip, ', ') 
                FROM (
                    SELECT DISTINCT A.Tip 
                    FROM ALERGII A 
                    JOIN FISA_MEDICALA FM ON A.Id_Alergie = FM.Id_Alergie 
                    WHERE FM.Id_Animal = :aid
                ) AS T_AlergiiTip
            ) AS Lista_Tip_Alergii,

            (
                SELECT STRING_AGG(Simptome, ', ') 
                FROM (
                    SELECT DISTINCT A.Simptome 
                    FROM ALERGII A 
                    JOIN FISA_MEDICALA FM ON A.Id_Alergie = FM.Id_Alergie 
                    WHERE FM.Id_Animal = :aid
                ) AS T_AlergiiSimp
            ) AS Lista_Simptome,
            
            (
                SELECT STRING_AGG(Tratament_recomandat, ', ') 
                FROM (
                    SELECT DISTINCT A.Tratament_recomandat 
                    FROM ALERGII A 
                    JOIN FISA_MEDICALA FM ON A.Id_Alergie = FM.Id_Alergie 
                    WHERE FM.Id_Animal = :aid
                ) AS T_AlergiiTrat
            ) AS Lista_Tratamente_Alergii,

            -- === 3. MEDICAMENTE (Lista Unică) ===
            (
                SELECT STRING_AGG(Nume_Medicamente, ', ') 
                FROM (
                    SELECT DISTINCT M.Nume_Medicamente 
                    FROM MEDICAMENTE M 
                    JOIN FISA_MEDICALA FM ON M.Id_medicamente = FM.Id_medicamente 
                    WHERE FM.Id_Animal = :aid
                ) AS T_MedNume
            ) AS Lista_Nume_Medicamente,

            (
                SELECT STRING_AGG(Doza_recomandată, ', ') 
                FROM (
                    SELECT DISTINCT M.Doza_recomandată 
                    FROM MEDICAMENTE M 
                    JOIN FISA_MEDICALA FM ON M.Id_medicamente = FM.Id_medicamente 
                    WHERE FM.Id_Animal = :aid
                ) AS T_MedDoza
            ) AS Lista_Doze,

            (
                SELECT STRING_AGG(Frecvență_administrarezi, ', ') 
                FROM (
                    SELECT DISTINCT M.Frecvență_administrarezi 
                    FROM MEDICAMENTE M 
                    JOIN FISA_MEDICALA FM ON M.Id_medicamente = FM.Id_medicamente 
                    WHERE FM.Id_Animal = :aid
                ) AS T_MedFrec
            ) AS Lista_Frecvente,

            -- === 4. ISTORIC MEDICAL (Lista Unică - Vaccinuri, Deparazitări) ===
            (
            SELECT STRING_AGG(Data_vizite, ', ') 
                FROM (
                    SELECT DISTINCT CONVERT(varchar, IM.Data_vizite) as Data_vizite
                    FROM ISTORIC_MEDICAL IM 
                    JOIN FISA_MEDICALA FM ON IM.Id_istoricmedical = FM.Id_istoricmedical 
                    WHERE FM.Id_Animal = :aid
                ) AS T_DataVizite
            ) AS Lista_Data_Vizite,

            (
                SELECT STRING_AGG(Vaccinări, ', ') 
                FROM (
                    SELECT DISTINCT IM.Vaccinări 
                    FROM ISTORIC_MEDICAL IM 
                    JOIN FISA_MEDICALA FM ON IM.Id_istoricmedical = FM.Id_istoricmedical 
                    WHERE FM.Id_Animal = :aid
                ) AS T_Vaccin
            ) AS Lista_Vaccinări,

            (
                SELECT STRING_AGG(Data_vaccinare, ', ') 
                FROM (
                    SELECT DISTINCT CONVERT(varchar, IM.Data_vaccinare) as Data_vaccinare
                    FROM ISTORIC_MEDICAL IM 
                    JOIN FISA_MEDICALA FM ON IM.Id_istoricmedical = FM.Id_istoricmedical 
                    WHERE FM.Id_Animal = :aid
                ) AS T_DataVacc
            ) AS Lista_Data_Vaccinare,

            (
                SELECT STRING_AGG(Tipuri_Deparazitări, ', ') 
                FROM (
                    SELECT DISTINCT IM.Tipuri_Deparazitări 
                    FROM ISTORIC_MEDICAL IM 
                    JOIN FISA_MEDICALA FM ON IM.Id_istoricmedical = FM.Id_istoricmedical 
                    WHERE FM.Id_Animal = :aid
                ) AS T_Depara
            ) AS Lista_Tipuri_Deparazitări,

            (
                SELECT STRING_AGG(Conditii_Speciale, ', ') 
                FROM (
                    SELECT DISTINCT IM.Conditii_Speciale 
                    FROM ISTORIC_MEDICAL IM 
                    JOIN FISA_MEDICALA FM ON IM.Id_istoricmedical = FM.Id_istoricmedical 
                    WHERE FM.Id_Animal = :aid
                ) AS T_Conditii
            ) AS Lista_Conditii_Speciale

        """

        # Executăm interogarea folosind ID-ul animalului curent
        report_row = db.session.execute(
            text(sql_medical_report), {"aid": current_animal_id}
        ).first()

        # MODIFICARE 3: Transformăm rândul SQL într-un dicționar Python pentru Jinja
        medical_report = {}
        if report_row:
            # _mapping ne permite să transformăm rezultatul într-un dicționar cu chei (numele coloanelor)
            medical_report = dict(report_row._mapping)

        return fl.render_template(
            "animal.html",
            user=user_data,
            setup_needed_animal=setup_needed_animal,  # ARATĂ CARDURILE
            numeanimal=result[0],
            specianimal=result[1],
            rasaanimal=result[2],
            varstaanimal=result[3],
            sexanimal=result[4],
            medical_report=medical_report,
            current_animal_id=current_animal_id,
        )
    else:
        # Nu avem date -> setup_needed = True -> ARATĂ FORMULARUL
        return fl.render_template(
            "animal.html",
            user=user_data,
            setup_needed_animal=setup_needed_animal,
            numeanimal="",
            specianimal="",
            rasaanimal="",
            varstaanimal="",
            sexanimal="",
            alergii_data=[],
            pie_data=[],
            medical_report={},
            current_animal_id=None,
        )


@app.route("/animal/add-visit/<int:animal_id>", methods=["GET", "POST"])
def show_add_visit_form(animal_id):
    # Verificare de bază (autentificare)
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    # --- LOGICA DE PROCESARE (POST) ---
    if fl.request.method == "POST":
        try:
            # 1. Preluarea Datelor din Formular
            greutate = fl.request.form.get("greutate")
            temperatura = fl.request.form.get("temperatura")
            conditie_corporala = fl.request.form.get("conditie_corporala")

            simptome = fl.request.form.get("simptome")
            descriere = fl.request.form.get(
                "descriere"
            )  # Folosit ca descriere_animal/diagnostic

            tip_alergie = fl.request.form.get("tip")
            simptome_alergie = fl.request.form.get("simptome")
            tratament_alergie = fl.request.form.get("tratament")

            nume_medicament = fl.request.form.get("nume_medicament")
            tip_medicament = fl.request.form.get("tip_medicament")
            doza = fl.request.form.get("doza")
            frecventa = fl.request.form.get("frecventa")

            data_vizita = fl.request.form.get("data_vizita")
            tip_vaccinare = fl.request.form.get("tip_vaccinare")
            data_vaccinare = fl.request.form.get("data_vaccinare")
            tip_deparazitare = fl.request.form.get("tip_deparazitare")
            conditii_speciale = fl.request.form.get("conditii_speciale")

            # --- ÎNSERĂRI ÎN BD ---

            # 2. Inserare în EXAMINARI
            # 1. INSERT în EXAMINARI
            sql_insert_examinare = """
                INSERT INTO EXAMINARI 
                    (Greutate, Temperatură, Condiție_Corporală, Simptome, Descriere_animal) 
                OUTPUT INSERTED.Id_examinari
                VALUES 
                    (:g, :t, :cc, :s, :d);
            """

            id_examinare = db.session.execute(
                text(sql_insert_examinare),
                {
                    "g": greutate,
                    "t": temperatura,
                    "cc": conditie_corporala,
                    "s": simptome,
                    "d": descriere,
                },
            ).scalar()

            db.session.commit()

            # 2. INSERT în MEDICAMENTE
            sql_insert_medicament = """    
                INSERT INTO MEDICAMENTE
                    (Nume_Medicamente, Tip, Doza_recomandată, Frecvență_administrarezi) 
                OUTPUT INSERTED.Id_medicamente
                VALUES
                    (:n, :t, :d, :f);
            """

            id_medicament = db.session.execute(
                text(sql_insert_medicament),
                {
                    "n": nume_medicament,
                    "t": tip_medicament,
                    "d": doza,
                    "f": frecventa,
                },
            ).scalar()

            db.session.commit()

            # 3. Inserare în MEDICAMENTE (Se inserează doar dacă a fost specificat un nume de medicament)
            sql_istoric_medical = text(
                """
            INSERT INTO ISTORIC_MEDICAL
                (Data_vizite, Vaccinări, Data_vaccinare, Tipuri_Deparazitări, Conditii_Speciale)
            OUTPUT INSERTED.Id_IstoricMedical
            VALUES
                (:dv, :v, :dvacc, :td, :cs);
        """
            )

            id_istoric_medical = db.session.execute(
                sql_istoric_medical,
                {
                    "dv": data_vizita,
                    "v": tip_vaccinare,
                    "dvacc": data_vaccinare,
                    "td": tip_deparazitare,
                    "cs": conditii_speciale,
                },
            ).scalar()

            db.session.commit()

            sql_alergie = text(
                """
    INSERT INTO ALERGII
        (Tip, Simptome, Tratament_recomandat)
    OUTPUT INSERTED.Id_Alergie
    VALUES
        (:tip, :simptome, :tratament);
"""
            )

            id_alergie = db.session.execute(
                sql_alergie,
                {
                    "tip": tip_alergie,
                    "simptome": simptome_alergie,
                    "tratament": tratament_alergie,
                },
            ).scalar()

            db.session.commit()

            # 4. Actualizarea FISA_MEDICALA
            # Notă: Această logică este simplificată!
            # Într-un sistem real, fiecare vizită ar trebui să fie o înregistrare nouă,
            # dar în contextul tău, actualizăm Fisa Medicala existentă a animalului,
            # adăugând noile ID-uri la cele existente (dacă folosești relații 1-la-1)
            # sau actualizând câmpurile corespunzătoare.

            # Pentru simplitate, presupunem că vrem să adăugăm noile ID-uri la fișa animalului curent:
            sql_insert_fisa = """
            INSERT INTO FISA_MEDICALA 
                (Id_examinari, Id_medicamente, Id_Animal, Id_Alergie,Id_istoricmedical)
            VALUES
                (:ide, :idm, :aid, :ida, :idim)
            """

            db.session.execute(
                text(sql_insert_fisa),
                {
                    "ide": id_examinare,
                    "idm": id_medicament,
                    "aid": animal_id,
                    "ida": id_alergie,
                    "idim": id_istoric_medical,
                },
            )

            # 5. Commit și Feedback
            db.session.commit()
            fl.flash(f"Vizită salvată pentru animalul ID {animal_id}!", "success")

            # Redirecționează înapoi la pagina animalului
            return fl.redirect(fl.url_for("show_animal_page"))

        except Exception as e:
            db.session.rollback()

            # 💥 MODIFICARE 1: Afișăm eroarea în log-ul serverului (consolă)
            print(f"--- EROARE BAZA DE DATE ---")
            print(f"Vizită eșuată pentru animal ID {animal_id}. Detaliu: {e}")
            print(f"---------------------------")

            # 💥 MODIFICARE 2: Afișăm o parte din eroare utilizatorului
            fl.flash(
                f"Eroare la salvare. Verificați tipul datelor introduse. Detaliu: {e}",
                "danger",
            )

            # Redirecționează înapoi la formular pentru a nu pierde datele
            return fl.redirect(fl.url_for("show_add_visit_form", animal_id=animal_id))

    # --- LOGICA DE AFIȘARE (GET) ---
    # Într-un sistem real, ar trebui să te asiguri că animal_id este valid și că aparține user-ului.

    # 💥 Notă: Parametrul 'animal_id' este necesar și în formularul HTML pentru acțiune!
    return fl.render_template("Adding_new_interogation.html", animal_id=animal_id)


@app.route("/animal/delete-last/<int:animal_id>", methods=["POST"])
def delete_last_visit(animal_id):
    # Verificare securitate
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    try:
        # 1. Găsim ID-ul ultimei vizite (Cea mai recentă Fișă Medicală)
        # Folosim TOP 1 și ORDER BY DESC pentru a lua ultima inserată
        sql_find_last = """
            SELECT TOP 1 Id_fisa_medicala 
            FROM FISA_MEDICALA 
            WHERE Id_Animal = :aid 
            ORDER BY Id_fisa_medicala DESC
        """
        result = db.session.execute(text(sql_find_last), {"aid": animal_id}).fetchone()

        if result:
            fisa_id_to_delete = result[0]

            # 2. Ștergem înregistrarea din FISA_MEDICALA
            # Notă: Dacă vrei să ștergi și din EXAMINARI/MEDICAMENTE, ar trebui să iei ID-urile lor înainte să ștergi fișa
            # Dar ștergerea din FISA_MEDICALA este suficientă pentru a o scoate din istoric.

            sql_delete = "DELETE FROM FISA_MEDICALA WHERE Id_fisa_medicala = :fid"
            db.session.execute(text(sql_delete), {"fid": fisa_id_to_delete})

            db.session.commit()
            fl.flash("Ultima vizită a fost ștearsă cu succes.", "warning")
        else:
            fl.flash("Nu există vizite de șters pentru acest animal.", "info")

    except Exception as e:
        db.session.rollback()
        fl.flash(f"Eroare la ștergere: {e}", "danger")
        print(f"Eroare delete: {e}")

    # Ne întoarcem la pagina animalului
    return fl.redirect(fl.url_for("show_animal_page"))


@app.route("/owner", methods=["GET", "POST"])
def show_owners_page():
    # 1. Verificare Autentificare
    if "user_id" not in fl.session:
        return fl.redirect(
            fl.url_for("show_login_page")
        )  # Asigură-te că numele rutei de login e corect

    user_id = fl.session["user_id"]

    # --- LOGICA DE POST (Când apeși butonul "Salvează") ---
    if fl.request.method == "POST":
        try:
            nume = fl.request.form["nume"]
            prenume = fl.request.form["prenume"]
            telefon = fl.request.form["telefon"]
            adresa = fl.request.form["adresa"]

            # Inserăm în STAPAN
            sql_insert = "INSERT INTO STAPAN (Nume, Prenume, Telefon, Adresa) VALUES (:n, :p, :t, :a)"
            db.session.execute(
                text(sql_insert), {"n": nume, "p": prenume, "t": telefon, "a": adresa}
            )

            sql_select_new_id = """
            SELECT Id_stapan FROM STAPAN 
            WHERE Nume=:nume AND Prenume=:prenume AND Telefon=:telefon AND Adresa=:adresa"""

            new_id = db.session.execute(
                text(sql_select_new_id),
                {
                    "nume": nume,
                    "prenume": prenume,
                    "telefon": telefon,
                    "adresa": adresa,
                },
            ).scalar()

            sql_check = """

        SELECT Id_user FROM FISA_MEDICALA

        WHERE Id_user = :user_id
          """
            rezultat = db.session.execute(
                text(sql_check), {"user_id": user_id}
            ).fetchone()

            if not rezultat:

                sql_insert_fisa = """

                INSERT INTO FISA_MEDICALA (Id_user) VALUES (:user_id)

                """

            db.session.execute(text(sql_insert_fisa), {"user_id": user_id})

            db.session.commit()

            # Luăm ID-ul nou creat

            # Legăm de User
            sql_link = "UPDATE FISA_MEDICALA SET Id_stapan = :sid WHERE Id_user = :uid"
            db.session.execute(text(sql_link), {"sid": new_id, "uid": user_id})

            db.session.commit()
            fl.flash("Date salvate cu succes!", "success")

            # Refresh la pagina ca să vedem Cardurile
            return fl.redirect(fl.url_for("show_owners_page"))

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare: {e}", "danger")

    # --- LOGICA DE GET (Afișare Pagină) ---

    # 2. Verificăm dacă avem date legate de acest user
    # Facem JOIN direct intre USER_ACCOUNT si STAPAN
    sql_get_data = """
        SELECT S.Nume, S.Prenume, S.Telefon, S.Adresa
        FROM FISA_MEDICALA FM
        FULL JOIN STAPAN S ON FM.Id_stapan = S.Id_stapan
        WHERE FM.Id_user = :uid
    """
    result = db.session.execute(text(sql_get_data), {"uid": user_id}).fetchone()

    # 3. Pregătim datele pentru Template
    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    # Daca avem rezultat, înseamnă că omul și-a completat datele -> setup_needed = False
    if result and result[0] is not None:
        return fl.render_template(
            "owner.html",
            user=user_data,
            setup_needed_owner=False,  # ARATĂ CARDURILE
            numeowner=result[0],
            prenumeowner=result[1],
            telefonowner=result[2],
            adresaowner=result[3],
        )
    else:
        # Nu avem date -> setup_needed = True -> ARATĂ FORMULARUL
        return fl.render_template(
            "owner.html",
            user=user_data,
            setup_needed_owner=True,
            numeowner="",
            prenumeowner="",
            telefonowner="",
            adresaowner="",
            alergii_data=[],
            pie_data=[],
        )


# --- Rute nefolosite (comentate) ---
# @app.route("/save-programare", methods=["POST"])
# ...
# @app.route("/save-programare")
# ...


@app.route("/logout")
def logout():
    fl.session.clear()
    return fl.redirect(fl.url_for("show_login_page"))


@app.route("/profile", methods=["GET", "POST"])
def show_profile_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]

    # --- LOGICA DE SALVARE (POST) ---
    if fl.request.method == "POST":
        try:
            # 1. Preluarea Datelor Text
            nume = fl.request.form.get("nume")
            prenume = fl.request.form.get("prenume")
            telefon = fl.request.form.get("telefon")
            adresa = fl.request.form.get("adresa")

            # 2. Gestionarea Imaginii (Upload)
            file = fl.request.files.get("file_poza")
            upload_succeeded = False

            if file and file.filename:
                try:
                    # A. Salvarea fișierului pe disc
                    filename = secure_filename(file.filename)
                    save_path = os.path.join(app.root_path, "static/img", filename)
                    file.save(save_path)

                    # B. Pregătirea URL-ului pentru DB și Front-end
                    new_pic_url = fl.url_for("static", filename=f"img/{filename}")

                    # C. ACTUALIZAREA CRITICĂ A BAZEI DE DATE
                    db.session.execute(
                        text(
                            "UPDATE USER_ACCOUNT SET Profile_Pic = :pic WHERE Id_user = :uid"
                        ),
                        {"pic": new_pic_url, "uid": user_id},
                    )

                    # D. Actualizare Sesiune (pentru Topbar)
                    fl.session["profile_pic"] = new_pic_url

                    upload_succeeded = True
                    fl.flash("Poza de profil a fost încărcată.", "info")

                except Exception as e:
                    fl.flash(
                        f"Eroare la încărcarea pozei pe server sau actualizarea DB: {e}",
                        "danger",
                    )
                    print(f"Eroare upload: {e}")

            # 3. Actualizarea Datelor Personale (STAPAN)
            # Verificăm dacă există deja date în STAPAN
            check_stapan = db.session.execute(
                text(
                    "SELECT S.Id_stapan FROM STAPAN S LEFT JOIN FISA_MEDICALA FM ON S.Id_stapan = FM.Id_stapan WHERE FM.Id_user = :uid"
                ),
                {"uid": user_id},
            ).fetchone()

            if check_stapan:
                # Update
                sql_update = """
                    UPDATE STAPAN 
                    SET Nume = :n, Prenume = :p, Telefon = :t, Adresa = :a 
                    WHERE Id_stapan = :uid
                """
                db.session.execute(
                    text(sql_update),
                    {
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                        "uid": user_id,
                    },
                )
            else:
                # Insert (dacă e prima dată când completează)
                sql_insert = """
                    INSERT INTO STAPAN (Id_user, Nume, Prenume, Telefon, Adresa)
                    VALUES (:uid, :n, :p, :t, :a)
                """
                db.session.execute(
                    text(sql_insert),
                    {
                        "uid": user_id,
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                    },
                )

            db.session.commit()
            if not upload_succeeded:
                fl.flash("Profil actualizat cu succes!", "success")

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare la actualizare: {e}", "danger")
            print(e)

    # --- LOGICA DE AFIȘARE (GET) ---
    # 1. Luăm datele userului (username, email, poza)
    sql_user = (
        "SELECT Username, Email, Profile_Pic FROM USER_ACCOUNT WHERE Id_user = :uid"
    )
    user_res = db.session.execute(text(sql_user), {"uid": user_id}).fetchone()

    pic_url_from_db = (
        user_res[2]
        if user_res[2]
        else fl.url_for("static", filename="img/undraw_profile.svg")
    )

    # FIX: Adăugăm un timestamp la URL-ul pozei
    cache_buster = int(time.time())
    final_pic_url = f"{pic_url_from_db}?v={cache_buster}"

    user_data = {
        "username": user_res[0],
        "email": user_res[1],
        # Aici folosești indexul coloanei nou adăugate (indexul 2)
        "profile_picture_url": final_pic_url,
    }

    fl.session["profile_pic"] = final_pic_url

    # 2. Luăm datele detaliate (STAPAN)
    sql_stapan = "SELECT S.Nume, S.Prenume, S.Telefon, S.Adresa FROM STAPAN S LEFT JOIN FISA_MEDICALA FM ON S.Id_stapan = FM.Id_stapan WHERE FM.Id_user = :uid"
    stapan_res = db.session.execute(text(sql_stapan), {"uid": user_id}).fetchone()

    stapan_data = {
        "nume": stapan_res[0] if stapan_res else "",
        "prenume": stapan_res[1] if stapan_res else "",
        "telefon": stapan_res[2] if stapan_res else "",
        "adresa": stapan_res[3] if stapan_res else "",
    }

    return fl.render_template("profile.html", user=user_data, stapan=stapan_data)


@app.route("/settings-page")
def show_settings_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    return fl.render_template("settings_page.html", user=user_data)


@app.route("/edit_animal/<int:animal_id>")
def edit_animal(animal_id):
    # Încarcă datele animalului din DB dacă vrei să precompletezi — opțional
    fl.session["setup_needed_animal"] = True
    return fl.redirect(fl.url_for("show_animal_page"))


@app.route("/search")
def search_animal():
    # 1. Preluăm termenul de căutare
    query = fl.request.args.get("q", "").strip()

    if not query:
        fl.flash("Te rog introdu un termen de căutare.", "warning")
        return fl.redirect(fl.url_for("show_animal_page"))  # Sau index

    # 2. Căutăm în baza de date (Case Insensitive cu LIKE)
    # Căutăm după Nume Animal SAU Nume Stăpân
    sql_search = """
        SELECT A.Id_animal, A.Nume, A.Rasa,A.Specie,A.Varsta,
                S.Nume, S.Prenume, S.Telefon,S.Adresa
        FROM ANIMAL A
        LEFT JOIN FISA_MEDICALA FM ON A.Id_animal = FM.Id_Animal
        LEFT JOIN STAPAN S ON FM.Id_stapan = S.Id_stapan -- Presupunând legătura prin User/Fișă
        WHERE A.Nume LIKE :q 
              OR S.Nume LIKE :q
              OR S.Prenume LIKE :q
    """

    # Folosim wildcard-uri (%) pentru căutare parțială
    search_term = f"%{query}%"
    results = db.session.execute(text(sql_search), {"q": search_term}).fetchall()

    # 3. Logica de Redirecționare
    if len(results) == 1:
        # CAZUL PERFECT: Am găsit exact un animal
        animal_id = results[0].Id_animal

        # Redirecționăm către dashboard-ul acelui animal, setând sesiunea sau parametrul
        # Important: Trebuie să modifici show_animal_page să accepte un ID opțional
        # Pentru moment, facem redirect cu parametru URL (vezi Pasul 3)
        return fl.redirect(fl.url_for("show_animal_page", id=animal_id))

    elif len(results) > 1:
        # Am găsit mai mulți -> Ar trebui să afișăm o listă (putem face asta mai târziu)
        fl.flash(
            f"Am găsit {len(results)} animale cu numele '{query}'. Afișăm primul găsit.",
            "info",
        )
        # Deocamdată luăm primul pentru simplitate
        return fl.redirect(
            fl.url_for("show_animal_page", id=results[0].Id_animal)
        )

    else:
        # Nu am găsit nimic
        fl.flash(f"Nu am găsit niciun animal cu numele '{query}'.", "danger")
        return fl.redirect(fl.url_for("show_animal_page"))


if __name__ == "__main__":
    app.run(debug=True)
