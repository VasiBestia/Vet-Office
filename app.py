import flask as fl
import sys
from flask_sqlalchemy import SQLAlchemy
import pyodbc
import re
import os
import bcrypt
import time
import uuid
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from datetime import datetime, timedelta
from dotenv import load_dotenv
from sqlalchemy import text
from werkzeug.utils import secure_filename

load_dotenv()

# --- INIȚIALIZARE ȘI CONFIGURARE APLICAȚIE ---

app = fl.Flask(__name__)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'), # CORECT
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), # CORECT
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

app.config["SECRET_KEY"] = "o_cheie_secreta_foarte_complicata"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False

Session(app)

# Asigură-te că string-ul de conectare este corect pentru PC-ul tău
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mssql+pyodbc:///?odbc_connect=DRIVER={ODBC+Driver+17+for+SQL+Server};SERVER=VASIVBM\\SQLEXPRESS;DATABASE=CabinetVeterinar;Trusted_Connection=yes;"
)

db = SQLAlchemy(app)


# =======================================================
# --- LOGICA 1: ÎNREGISTRARE (GET + POST) ---
# =======================================================

@app.route("/register", methods=["GET", "POST"])
def show_register_page():
    # --- CAZUL 1: POST (Când apeși butonul "Register") ---
    if fl.request.method == "POST":
        username = fl.request.form.get("username")
        email = fl.request.form.get("email")
        password = fl.request.form.get("password")
        retypepassword = fl.request.form.get("retype_password")

        # 1. Validări
        if not username or not email or not password or password != retypepassword:
            return "ERROR: Completează toate câmpurile și verifică parolele.", 400

        if len(password) < 8:
            return "ERROR: Parola trebuie să aibă minim 8 caractere.", 400

        try:
            # 2. Verificăm dacă userul există deja
            sql_check = "SELECT Username FROM USER_ACCOUNT WHERE Username = :user OR Email = :email"
            rezultat = db.session.execute(text(sql_check), {"user": username, "email": email}).fetchone()

            if rezultat:
                return "ERROR: Userul sau emailul există deja.", 409

            # 3. CRIPTARE CORECTĂ (Rezolvarea "literelor chinezești")
            password_bytes = password.encode("utf-8")
            # Adăugăm .decode('utf-8') la final pentru a-l face String, nu Bytes
            hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

            # 4. Inserare în Baza de Date
            sql_insert = "INSERT INTO USER_ACCOUNT (Username, Email, Parola) VALUES (:user, :email, :password)"
            db.session.execute(
                text(sql_insert),
                {"user": username, "email": email, "password": hashed_password}
            )
            db.session.commit()

            # Succes -> Trimitem la Login (folosind numele funcției unificate de login)
            return fl.redirect(fl.url_for("show_login_page"))

        except Exception as ex:
            print(f"Eroare BD: {ex}", file=sys.stderr)
            return f"Eroare de server: {ex}", 500

    # --- CAZUL 2: GET (Afișarea paginii) ---
    else:
        return fl.render_template("register.html")


# =======================================================
# --- LOGICA 2: AUTENTIFICARE ---
# =======================================================


@app.route("/login", methods=["GET", "POST"])
def show_login_page():
    # --- CAZUL 1: POST (Când apasă butonul de Login) ---
    if fl.request.method == "POST":
        email = fl.request.form.get("email")
        password = fl.request.form.get("password")
        remember_me = fl.request.form.get("remember_me")

        if not email or not password:
            fl.flash("Introduceți toate câmpurile.", "danger")
            return fl.redirect(fl.url_for("login_page"))

        try:
            sql_select = "SELECT Parola, Username, Id_user FROM USER_ACCOUNT WHERE Email = :email"
            user_record = db.session.execute(
                text(sql_select), {"email": email}
            ).fetchone()

            if not user_record:
                fl.flash("Email sau parolă incorectă.", "danger")
                return fl.redirect(fl.url_for("login_page"))

            stored_hashed_password = user_record[0]
            username = user_record[1]
            user_id = user_record[2]

            # Verificare parolă
            if not bcrypt.checkpw(
                password.encode("utf-8"), stored_hashed_password.encode("utf-8")
            ):
                fl.flash("Email sau parolă incorectă.", "danger")
                return fl.redirect(fl.url_for("login_page"))

            # LOGIN SUCCES - Setăm sesiunea
            fl.session["logged_in"] = True
            fl.session["user_id"] = user_id
            fl.session["username"] = username
            fl.session["email"] = email

            response = fl.make_response(fl.redirect(fl.url_for("index")))

            # Remember Me Cookie
            if remember_me:
                expires_date = datetime.now() + timedelta(days=30)
                response.set_cookie(
                    "remember_email", email, expires=expires_date, httponly=True
                )
            else:
                response.delete_cookie("remember_email")

            return response

        except Exception as e:
            print(f"Eroare la autentificare: {e}")
            fl.flash("Eroare internă a serverului.", "danger")
            return fl.redirect(fl.url_for("login_page"))

    # --- CAZUL 2: GET (Afișarea paginii de Login) ---
    else:
        remembered_email = fl.request.cookies.get("remember_email")
        return fl.render_template("login.html", remembered_email=remembered_email)


# ... (Rutele de Forgot Password / Google Login rămân neschimbate, logica lor e ok) ...
# ... (Am omis codul Google/Forgot Password aici pentru a scurta, dar trebuie păstrat în fișierul final) ...
# --- RUTA 1: Butonul de Login trimite aici ---
@app.route("/login/google")
def google_login():
    # Google are nevoie de un URL de callback (unde să se întoarcă)
    redirect_uri = fl.url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


# --- RUTA 2: Handler-ul (Procesare Login Google) ---
@app.route("/login/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo")

        # 1. Luăm datele de la Google
        email = user_info.get("email")
        nume = user_info.get("name")
        picture = user_info.get("picture")

        # 2. Verificăm dacă userul există în DB
        sql_select = "SELECT * FROM USER_ACCOUNT WHERE Email = :email"
        existing_user = db.session.execute(
            text(sql_select), {"email": email}
        ).fetchone()

        user_id = None
        user_username = None
        user_poza = None

        if existing_user:
            # Userul există, îi luăm ID-ul și Poza curentă
            # Indexele: 0=Id, 1=Username, 2=Email, 3=Parola, 4=Profile_Pic
            user_id = existing_user[0]
            user_username = existing_user[1]

            db_pic = existing_user[4]
            user_poza = db_pic if db_pic else picture

        else:
            # 3. User NOU -> Îl creăm automat
            # Generăm parolă random UUID ca să nu fie NULL în bază
            random_password = str(uuid.uuid4())
            hashed_password = bcrypt.hashpw(
                random_password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

            sql_insert = """
                INSERT INTO USER_ACCOUNT (Email, Username, Parola, Profile_Pic) 
                VALUES (:email, :username, :parola, :poza)
            """
            db.session.execute(
                text(sql_insert),
                {
                    "email": email,
                    "username": nume,
                    "parola": hashed_password,
                    "poza": picture,
                },
            )
            db.session.commit()

            # Luăm ID-ul noului user creat
            new_user = db.session.execute(text(sql_select), {"email": email}).fetchone()
            user_id = new_user[0]
            user_username = nume
            user_poza = picture

        # 4. SETARE SESIUNE
        fl.session["logged_in"] = True
        fl.session["user_id"] = user_id
        fl.session["username"] = user_username
        fl.session["email"] = email
        fl.session["profile_pic"] = user_poza

        return fl.redirect(fl.url_for("index"))

    except Exception as e:
        print(f"Eroare Google Login: {e}")
        return "Eroare la autentificarea cu Google.", 500


@app.route("/forgot-password")
def show_forgot_password_page():
    return fl.render_template("forgot-password.html")


@app.route("/forgot-passwordpage", methods=["POST"])
def forgot_password():
    email = fl.request.form.get("email")

    if not email:
        return ("ERROR: Te rog completează adresa de email.", 400)

    try:
        sql_check_email = "SELECT Email FROM USER_ACCOUNT WHERE Email = :email"
        user_record = db.session.execute(
            text(sql_check_email), {"email": email}
        ).fetchone()

        if user_record:
            # Salvăm email-ul în sesiune pentru pasul următor
            fl.session["reset_email"] = email
            return fl.redirect(fl.url_for("show_retype_password_page"))
        else:
            return ("ERROR: Email-ul nu a fost găsit în baza de date.", 409)

    except Exception as ex:
        print(f"Eroare BD: {ex}")
        return "Eroare server.", 500


@app.route("/retype-password")
def show_retype_password_page():
    return fl.render_template("retype_password.html")


@app.route("/retype-password", methods=["POST"])
def retype_password():
    email_to_update = fl.session.get("reset_email")
    password = fl.request.form.get("password")
    retype_password = fl.request.form.get("retype_password")

    if not email_to_update:
        return ("ERROR: Sesiunea a expirat.", 403)

    if not password or not retype_password or password != retype_password:
        return ("ERROR: Parolele nu se potrivesc.", 400)

    try:
        password_bytes = password.encode("utf-8")
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        sql_update = "UPDATE USER_ACCOUNT SET Parola = :password WHERE Email = :email"
        db.session.execute(
            text(sql_update), {"password": hashed_password, "email": email_to_update}
        )
        db.session.commit()

        fl.session.pop("reset_email", None)
        return fl.redirect(fl.url_for("show_login_page"))

    except Exception as ex:
        db.session.rollback()
        print(f"Eroare resetare: {ex}")
        return "Eroare server.", 500


# =======================================================
# --- LOGICA 5: DASHBOARD GENERAL ---
# =======================================================


@app.route("/")
def index():
    if "logged_in" not in fl.session or not fl.session["logged_in"]:
        return fl.redirect(fl.url_for("show_login_page"))

    # 1. Statistici Generale (Carduri de sus)
    # Număr total de animale
    card_animale = (
        db.session.execute(text("SELECT COUNT(Id_Animal) FROM ANIMAL")).scalar() or 0
    )

    # Număr total de stăpâni
    card_stapani = (
        db.session.execute(text("SELECT COUNT(Id_stapan) FROM STAPAN")).scalar() or 0
    )

    # Număr total de Fișe Medicale (Consultații Generale)
    card_consultatii = (
        db.session.execute(text("SELECT COUNT(Id_fisa) FROM FISA_MEDICALA")).scalar()
        or 0
    )

    # Consultații în luna curentă (Activitate recentă)
    sql_luna = """
        SELECT COUNT(Id_fisa)
        FROM FISA_MEDICALA
        WHERE MONTH(Data_vizite) = MONTH(GETDATE()) AND YEAR(Data_vizite) = YEAR(GETDATE())
    """
    # Notă: Asigură-te că numele coloanei de dată din FISA_MEDICALA este corect (ex: Data_vizite sau Data)
    try:
        card_activitate_luna = db.session.execute(text(sql_luna)).scalar() or 0
    except:
        card_activitate_luna = 0  # Fallback dacă coloana de dată are alt nume

    # 2. Date pentru Grafice
    # Grafic Pie: Repartiția Animalelor pe Specii (Mult mai util decât examinări vs intervenții)
    sql_pie = "SELECT Specie, COUNT(*) as Nr FROM ANIMAL GROUP BY Specie"
    rezultat_pie = db.session.execute(text(sql_pie)).fetchall()

    # Pregătim datele pentru Chart.js
    pie_labels = [row[0] for row in rezultat_pie]  # Ex: ['Caine', 'Pisica']
    pie_values = [row[1] for row in rezultat_pie]  # Ex: [10, 5]

    # Avatar User
    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/default_avatar.jpg")
        ),
    }

    return fl.render_template(
        "dashboard.html",
        user=user_data,
        nr_animale=card_animale,
        nr_stapani=card_stapani,
        nr_consultatii=card_consultatii,  # Înlocuiește examinările vechi
        nr_activitate_luna=card_activitate_luna,  # Înlocuiește intervențiile
        pie_labels=pie_labels,
        pie_values=pie_values,
    )


# =======================================================
# --- LOGICA 6: PAGINA ANIMAL (MODIFICARE MAJORĂ SQL) ---
# =======================================================


@app.route("/animal", methods=["GET", "POST"])
def show_animal_page():
    # 1. Verificare Autentificare
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]
    search_animal_id = fl.request.args.get("id", type=int)

    # --- LOGICA POST: SALVARE ANIMAL NOU ---
    if fl.request.method == "POST":
        try:
            # A. Preluăm datele din formular
            nume = fl.request.form.get("nume")
            specie = fl.request.form.get("specie")
            rasa = fl.request.form.get("rasa")
            varsta = fl.request.form.get("varsta")
            sex = fl.request.form.get("sex")

            # B. Găsim ID-ul Stăpânului (pe baza userului logat)
            sql_find_stapan = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
            stapan_id = db.session.execute(
                text(sql_find_stapan), {"uid": user_id}
            ).scalar()

            if not stapan_id:
                fl.flash(
                    "Eroare: Trebuie să îți completezi profilul de stăpân mai întâi!",
                    "warning",
                )
                return fl.redirect(fl.url_for("show_owners_page"))

            # C. Inserăm Animalul în Baza de Date
            sql_insert = """
                INSERT INTO ANIMAL (Nume, Specie, Rasa, Varsta, Sex, Id_stapan) 
                VALUES (:n, :s, :r, :v, :x, :sid)
            """
            db.session.execute(
                text(sql_insert),
                {
                    "n": nume,
                    "s": specie,
                    "r": rasa,
                    "v": varsta,
                    "x": sex,
                    "sid": stapan_id,
                },
            )
            db.session.commit()

            # D. (Opțional) Creăm o primă fișă medicală goală sau luăm ID-ul noului animal
            # Găsim ID-ul animalului nou creat pentru a redirecționa către el
            sql_get_new_id = "SELECT TOP 1 Id_animal FROM ANIMAL WHERE Id_stapan = :sid ORDER BY Id_animal DESC"
            new_animal_id = db.session.execute(
                text(sql_get_new_id), {"sid": stapan_id}
            ).scalar()

            fl.flash("Animal adăugat cu succes!", "success")
            return fl.redirect(fl.url_for("show_animal_page", id=new_animal_id))

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare la salvarea animalului: {e}", "danger")
            print(f"Eroare SQL: {e}")

    # --- LOGICA GET: AFIȘARE PAGINĂ ---

    current_animal_id = None
    if search_animal_id:
        current_animal_id = search_animal_id
    else:
        # Căutăm animalul principal (prin Stăpân)
        sql_find = """
            SELECT TOP 1 A.Id_animal 
            FROM ANIMAL A 
            JOIN STAPAN S ON A.Id_stapan = S.Id_stapan 
            WHERE S.Id_user = :uid
        """
        current_animal_id = db.session.execute(
            text(sql_find), {"uid": user_id}
        ).scalar()

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    if current_animal_id:
        setup_needed_animal = False

        # A. Date Generale Animal (Carduri Sus)
        sql_animal = (
            "SELECT Nume, Specie, Rasa, Varsta, Sex FROM ANIMAL WHERE Id_animal = :aid"
        )
        animal_res = db.session.execute(
            text(sql_animal), {"aid": current_animal_id}
        ).fetchone()

        # B. Istoric Vizite (Din tabelul FISA_MEDICALA)
        # Asigură-te că numele coloanelor corespund cu ce ai în DB (Id_fisa vs Id_fisa_medicala)
        sql_istoric = """
            SELECT 
                Id_fisa, 
                Data_vizita, 
                Motiv_vizita, 
                Diagnostic, 
                Greutate, 
                Temperatura
            FROM FISA_MEDICALA
            WHERE Id_animal = :aid
            ORDER BY Data_vizite DESC
        """
        try:
            istoric_list = db.session.execute(
                text(sql_istoric), {"aid": current_animal_id}
            ).fetchall()
        except:
            istoric_list = []  # Dacă tabelul e gol sau are alte nume de coloane

        # C. Vaccinări
        vaccin_list = []
        try:
            sql_vaccin = "SELECT Data_vaccinare, Tip_vaccin, Data_rapel FROM VACCINARI WHERE Id_animal = :aid"
            vaccin_list = db.session.execute(
                text(sql_vaccin), {"aid": current_animal_id}
            ).fetchall()
        except:
            pass

        return fl.render_template(
            "animal.html",
            user=user_data,
            setup_needed_animal=False,
            animal=animal_res,
            istoric_list=istoric_list,
            vaccin_list=vaccin_list,
            current_animal_id=current_animal_id,
        )

    else:
        # Mod Setup (Nu are animal -> Arată formularul de adăugare)
        return fl.render_template(
            "animal.html", user=user_data, setup_needed_animal=True
        )


# =======================================================
# --- LOGICA 7: PAGINA STAPAN (REFACUTĂ PE ID_USER) ---
# =======================================================


@app.route("/owner", methods=["GET", "POST"])
def show_owners_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]

    # --- POST: Salvare Profil Stăpân ---
    if fl.request.method == "POST":
        try:
            nume = fl.request.form.get("nume")
            prenume = fl.request.form.get("prenume")
            telefon = fl.request.form.get("telefon")
            adresa = fl.request.form.get("adresa")

            # Verificăm direct după Id_user
            check_sql = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
            existing = db.session.execute(text(check_sql), {"uid": user_id}).fetchone()

            if existing:
                sql_upd = "UPDATE STAPAN SET Nume=:n, Prenume=:p, Telefon=:t, Adresa=:a WHERE Id_user=:uid"
                db.session.execute(
                    text(sql_upd),
                    {
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                        "uid": user_id,
                    },
                )
            else:
                sql_ins = "INSERT INTO STAPAN (Id_user, Nume, Prenume, Telefon, Adresa) VALUES (:uid, :n, :p, :t, :a)"
                db.session.execute(
                    text(sql_ins),
                    {
                        "uid": user_id,
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                    },
                )

            db.session.commit()
            return fl.redirect(fl.url_for("show_owners_page"))
        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare: {e}", "danger")

    # --- GET: Afișare ---
    sql_stapan = "SELECT Id_stapan, Nume, Prenume, Telefon, Adresa FROM STAPAN WHERE Id_user = :uid"
    stapan_res = db.session.execute(text(sql_stapan), {"uid": user_id}).fetchone()

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    if stapan_res:
        stapan_id = stapan_res[0]

        # Luăm animalele legate de acest stăpân
        sql_animale = "SELECT Id_animal, Nume, Specie, Rasa, Varsta, Sex FROM ANIMAL WHERE Id_stapan = :sid"
        animale_list = db.session.execute(
            text(sql_animale), {"sid": stapan_id}
        ).fetchall()

        # Statistici simple
        stats = {"nr_animale": len(animale_list), "total_vizite": 0}

        return fl.render_template(
            "owner.html",
            user=user_data,
            setup_needed_owner=False,
            stapan={
                "nume": stapan_res[1],
                "prenume": stapan_res[2],
                "telefon": stapan_res[3],
                "adresa": stapan_res[4],
            },
            animale_list=animale_list,
            stats=stats,
        )
    else:
        return fl.render_template("owner.html", user=user_data, setup_needed_owner=True)


# =======================================================
# --- LOGICA 8: CAUTARE (REFACUTĂ) ---
# =======================================================


@app.route("/search")
def search_animal():
    query = fl.request.args.get("q", "").strip()
    if not query:
        return fl.redirect(fl.url_for("show_animal_page"))

    # Căutare simplificată: JOIN între ANIMAL și STAPAN
    sql_search = """
        SELECT A.Id_animal
        FROM ANIMAL A
        JOIN STAPAN S ON A.Id_stapan = S.Id_stapan
        WHERE A.Nume LIKE :q OR S.Nume LIKE :q OR S.Prenume LIKE :q
    """
    search_term = f"%{query}%"
    results = db.session.execute(text(sql_search), {"q": search_term}).fetchall()

    if len(results) == 1:
        return fl.redirect(fl.url_for("show_animal_page", id=results[0].Id_animal))
    elif len(results) > 1:
        fl.flash(f"Găsite {len(results)} rezultate. Afișăm primul.", "info")
        return fl.redirect(fl.url_for("show_animal_page", id=results[0].Id_animal))
    else:
        fl.flash("Niciun rezultat găsit.", "danger")
        return fl.redirect(fl.url_for("show_animal_page"))


# =======================================================
# --- LOGICA 9: PROFIL USER (POZA + UPDATE STAPAN) ---
# =======================================================


@app.route("/profile", methods=["GET", "POST"])
def show_profile_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]

    if fl.request.method == "POST":
        try:
            # Update Date Personale (Direct in STAPAN folosind Id_user)
            nume = fl.request.form.get("nume")
            prenume = fl.request.form.get("prenume")
            telefon = fl.request.form.get("telefon")
            adresa = fl.request.form.get("adresa")

            # Verifica daca exista
            check_stapan = db.session.execute(
                text("SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"),
                {"uid": user_id},
            ).fetchone()

            if check_stapan:
                sql_update = "UPDATE STAPAN SET Nume=:n, Prenume=:p, Telefon=:t, Adresa=:a WHERE Id_user=:uid"
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
                sql_insert = "INSERT INTO STAPAN (Id_user, Nume, Prenume, Telefon, Adresa) VALUES (:uid, :n, :p, :t, :a)"
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

            # Update Poza (Rămâne la fel)
            file = fl.request.files.get("file_poza")
            if file and file.filename:
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.root_path, "static/img", filename)
                file.save(save_path)
                new_pic_url = fl.url_for("static", filename=f"img/{filename}")

                db.session.execute(
                    text(
                        "UPDATE USER_ACCOUNT SET Profile_Pic = :pic WHERE Id_user = :uid"
                    ),
                    {"pic": new_pic_url, "uid": user_id},
                )
                fl.session["profile_pic"] = new_pic_url

            db.session.commit()
            fl.flash("Profil actualizat!", "success")

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare: {e}", "danger")

    # GET logic - neschimbat vizual, doar SQL
    sql_user = (
        "SELECT Username, Email, Profile_Pic FROM USER_ACCOUNT WHERE Id_user = :uid"
    )
    user_res = db.session.execute(text(sql_user), {"uid": user_id}).fetchone()

    # Cache buster logic
    pic_url = (
        user_res[2]
        if user_res[2]
        else fl.url_for("static", filename="img/undraw_profile.svg")
    )
    final_pic_url = f"{pic_url}?v={int(time.time())}"
    fl.session["profile_pic"] = final_pic_url

    user_data = {
        "username": user_res[0],
        "email": user_res[1],
        "profile_picture_url": final_pic_url,
    }

    sql_stapan = (
        "SELECT Nume, Prenume, Telefon, Adresa FROM STAPAN WHERE Id_user = :uid"
    )
    stapan_res = db.session.execute(text(sql_stapan), {"uid": user_id}).fetchone()
    stapan_data = {
        "nume": stapan_res[0] if stapan_res else "",
        "prenume": stapan_res[1] if stapan_res else "",
        "telefon": stapan_res[2] if stapan_res else "",
        "adresa": stapan_res[3] if stapan_res else "",
    }

    return fl.render_template("profile.html", user=user_data, stapan=stapan_data)


# Rutele ramase (logout, settings, add-visit) raman neschimbate sau sunt minore
# app.py


@app.route("/animal/add-visit/<int:animal_id>", methods=["GET", "POST"])
def show_add_visit_form(animal_id):
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    # POST: SALVARE VIZITĂ NOUĂ
    if fl.request.method == "POST":
        try:
            # 1. Preluare date din formular
            # --- DATE GENERALE (FISA) ---
            data_vizita = fl.request.form.get("data_vizita")
            motiv = fl.request.form.get("motiv")  # Simptome
            diagnostic = fl.request.form.get("diagnostic")  # Descriere detaliată
            greutate = fl.request.form.get("greutate")
            temperatura = fl.request.form.get("temperatura")

            # --- DATE VACCINARE (Opțional) ---
            tip_vaccin = fl.request.form.get("tip_vaccin")
            data_rapel = fl.request.form.get("data_rapel")

            # --- 2. Inserare în FISA_MEDICALA ---
            sql_fisa = """
                INSERT INTO FISA_MEDICALA (Id_Animal, Data_vizite, Motiv_vizita, Diagnostic, Greutate, Temperatura)
                VALUES (:aid, :dv, :m, :d, :g, :t)
            """
            db.session.execute(
                text(sql_fisa),
                {
                    "aid": animal_id,
                    "dv": data_vizita,
                    "m": motiv,
                    "d": diagnostic,
                    "g": greutate,
                    "t": temperatura,
                },
            )

            # --- 3. Inserare în VACCINARI (Dacă s-a completat) ---
            if tip_vaccin:
                sql_vaccin = """
                    INSERT INTO VACCINARI (Id_animal, Data_vaccinare, Tip_vaccin, Data_rapel)
                    VALUES (:aid, :dv, :tv, :dr)
                """
                db.session.execute(
                    text(sql_vaccin),
                    {
                        "aid": animal_id,
                        "dv": data_vizita,  # Data vaccinării = data vizitei
                        "tv": tip_vaccin,
                        "dr": data_rapel,
                    },
                )

            db.session.commit()
            fl.flash("Vizită adăugată cu succes!", "success")
            return fl.redirect(fl.url_for("show_animal_page", id=animal_id))

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare la salvare: {e}", "danger")
            print(f"Eroare SQL Add Visit: {e}")

    # GET: Afișare Formular
    return fl.render_template("Adding_new_interogation.html", animal_id=animal_id)


@app.route("/animal/delete-last/<int:animal_id>", methods=["POST"])
def delete_last_visit(animal_id):
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))
    # Delete logic remains same (Deleting from FISA where Id_Animal matches)
    db.session.execute(
        text(
            "DELETE FROM FISA_MEDICALA WHERE Id_fisa_medicala = (SELECT TOP 1 Id_fisa_medicala FROM FISA_MEDICALA WHERE Id_Animal=:aid ORDER BY Id_fisa_medicala DESC)"
        ),
        {"aid": animal_id},
    )
    db.session.commit()
    return fl.redirect(fl.url_for("show_animal_page"))


@app.route("/appointments", methods=["GET", "POST"])
def show_appointments():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))
    
    user_id = fl.session["user_id"]

    # 1. Găsim ID-ul Stăpânului (pentru a filtra doar animalele lui)
    sql_stapan = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
    stapan_id = db.session.execute(text(sql_stapan), {"uid": user_id}).scalar()

    if not stapan_id:
        fl.flash("Completează profilul de stăpân pentru a face programări.", "warning")
        return fl.redirect(fl.url_for("show_owners_page"))

    # --- POST: ADAUGĂ PROGRAMARE NOUĂ ---
    if fl.request.method == "POST":
        try:
            animal_id = fl.request.form.get("animal_select")
            data_ora_str = fl.request.form.get("data_ora") # Format: 2023-12-01T14:30
            motiv = fl.request.form.get("motiv")

            # Convertim string-ul din HTML în datetime SQL
            data_ora = datetime.strptime(data_ora_str, '%Y-%m-%dT%H:%M')

            sql_insert = """
                INSERT INTO PROGRAMARI (Id_animal, Data_ora, Motiv, Status)
                VALUES (:aid, :do, :m, 'In Asteptare')
            """
            db.session.execute(text(sql_insert), {
                "aid": animal_id,
                "do": data_ora,
                "m": motiv
            })
            db.session.commit()
            fl.flash("Programare trimisă cu succes!", "success")
            
        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare programare: {e}", "danger")
            print(e)
        
        return fl.redirect(fl.url_for("show_appointments"))

    # --- GET: AFIȘARE LISTĂ ---
    
    # A. Luăm lista de animale pentru Dropdown (Formular)
    sql_animale = "SELECT Id_animal, Nume FROM ANIMAL WHERE Id_stapan = :sid"
    lista_animale = db.session.execute(text(sql_animale), {"sid": stapan_id}).fetchall()

    # B. Luăm Programările Viitoare (JOIN complex pentru a afișa numele animalului)
    sql_programari = """
        SELECT 
            P.Id_programare,
            P.Data_ora,
            P.Motiv,
            P.Status,
            A.Nume as NumeAnimal,
            A.Specie
        FROM PROGRAMARI P
        JOIN ANIMAL A ON P.Id_animal = A.Id_animal
        WHERE A.Id_stapan = :sid
        ORDER BY P.Data_ora ASC
    """
    lista_programari = db.session.execute(text(sql_programari), {"sid": stapan_id}).fetchall()

    # Statistici rapide pentru cardurile de sus
    nr_asteptare = sum(1 for p in lista_programari if p.Status == 'In Asteptare')
    nr_confirmet = sum(1 for p in lista_programari if p.Status == 'Confirmat')

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get("profile_pic", fl.url_for("static", filename="img/undraw_profile.svg"))
    }

    return fl.render_template("appointments.html", 
                              user=user_data,
                              lista_animale=lista_animale,
                              lista_programari=lista_programari,
                              stats={"asteptare": nr_asteptare, "confirmat": nr_confirmet})

# --- RUTA PENTRU ANULARE / STATUS ---
@app.route("/appointment/status/<int:app_id>/<string:new_status>")
def update_appointment_status(app_id, new_status):
    if "user_id" not in fl.session: return fl.redirect(fl.url_for("show_login_page"))
    
    try:
        db.session.execute(text("UPDATE PROGRAMARI SET Status = :s WHERE Id_programare = :id"), {"s": new_status, "id": app_id})
        db.session.commit()
        fl.flash(f"Status actualizat: {new_status}", "info")
    except Exception as e:
        fl.flash(f"Eroare: {e}", "danger")
        
    return fl.redirect(fl.url_for("show_appointments"))


@app.route("/logout")
def logout():
    fl.session.clear()
    return fl.redirect(fl.url_for("show_login_page"))


@app.route("/settings-page")
def show_settings_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))
    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get("profile_pic", ""),
    }
    return fl.render_template("settings_page.html", user=user_data)


if __name__ == "__main__":
    app.run(debug=True)
