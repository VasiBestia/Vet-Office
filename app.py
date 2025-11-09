import flask as fl
import sys  # Pentru a afișa erori clare în consolă
import pyodbc
import re  # Pentru validarea parolei

app = fl.Flask(__name__)

app.secret_key = "cheie_secreta_foarte_puternica_si_lunga"

# --- CONFIGURAȚIA GLOBALĂ DE BAZĂ DE DATE ---
SERVER = "VASIVBM\\SQLEXPRESS"
DATABASE = "CabinetVeterinar"
DRIVER = "{ODBC Driver 17 for SQL Server}"
CONN_STRING = (
    f"DRIVER={DRIVER};SERVER={SERVER};" 
    f"DATABASE={DATABASE};Trusted_Connection=yes;"
)


# --- LOGICA 1: ÎNREGISTRARE ---


@app.route("/register", methods=["POST"])
def register_user():
    username = fl.request.form.get("username")
    email = fl.request.form.get("email")
    password = fl.request.form.get("password")
    retypepassword = fl.request.form.get("retype_password")

    # 1. Validare de bază
    if not username or not email or not password or password != retypepassword:
        return (
            """ERROR: Please fill in all fields and ensure 
        that passwords match.""",
            400,
        )

    # 2. Validare complexitate Parola
    if len(password) < 8:
        return """ERROR: Password must be at least 8 characters long.""", 400

    special_chars = r'[!@#$%^&*(),.?":{}|<>]'
    if not re.search(special_chars, password):
        return (
            """ERROR: Password must contain 
        at least one special character.""",
            400,
        )

    if not any(char.isalpha() for char in password):
        return """ERROR: Password must contain at least one letter.""", 400

    if not any(char.isdigit() for char in password):
        return """ERROR: Password must contain at least one digit""", 400

    # 3. Validare domeniu Email
    valid_domains = ("@yahoo.com", "@gmail.com")
    if not email.lower().endswith(valid_domains):
        return (
            """ERROR: Email address 
        must be Yahoo or Gmail""",
            400,
        )

    try:
        conexiune = pyodbc.connect(CONN_STRING)
        cursor = conexiune.cursor()

        # 4. VERIFICARE UNICITATE (Bază de Date)
        cursor.execute(
            """
            SELECT Nume, Email FROM USER_ACCOUNT 
            WHERE Nume = ? OR Email = ?
        """,
            (username, email),
        )

        if cursor.fetchone():
            conexiune.close()
            return (
                """ERROR: Username or Email already exists in the 
            database.""",
                409,
            )

        # 5. INSERARE (Doar daca toate validarile au trecut)
        cursor.execute(
            "INSERT INTO USER_ACCOUNT (Nume, Email, Parola) VALUES (?, ?, ?)",
            (username, email, password),
        )
        conexiune.commit()
        conexiune.close()

        return "SUCCESS: User registered successfully!", 201

    except pyodbc.Error as ex:
        print(f"BD error: {ex}", file=sys.stderr)
        return "BD error: Registration server error.", 500


# --- LOGICA 2: AUTENTIFICARE ---


@app.route("/login", methods=["POST"])
def login_user():
    # Extrage datele din formular
    username = fl.request.form.get("username")
    password = fl.request.form.get("password")

    try:
        conexiune = pyodbc.connect(CONN_STRING)
        cursor = conexiune.cursor()

        cursor.execute(
            """
                       SELECT Nume FROM USER_ACCOUNT 
                       WHERE Nume = ? AND Parola = ?""",
            (username, password),
        )

        utilizator_gasit = cursor.fetchone()
        conexiune.close()

        if utilizator_gasit:
            user_id = utilizator_gasit[0]
            fl.session["user_id"] = user_id

            return fl.redirect("http://cabinet-veterinar-pet.local/")
        else:
            # Eșec - Credențiale incorecte.
            return "ERROR: Mismatching credentials", 401

    except pyodbc.Error as ex:
        print(f"BD error: {ex}", file=sys.stderr)
        return "Authentication server ERROR.", 500


# --- RUTA PRINCIPALĂ (Afișează pagina HTML) ---


@app.route("/save-programare", methods=["POST"])
def save_programare():
    # Preluarea datelor din formular
    owner_last_name = fl.request.form.get("OwnerLastName")
    owner_first_name = fl.request.form.get("OwnerFirstName")
    telephone = fl.request.form.get("Telephone")
    address = fl.request.form.get("Address")
    pet_name = fl.request.form.get("PetName")
    species = fl.request.form.get("Species")
    breed = fl.request.form.get("Breed")
    age = fl.request.form.get("Age")
    sex = fl.request.form.get("Sex")

    user_id = fl.session.get("user_id")

    if user_id is None:
        return fl.redirect("/login-page")

    try:
        conexiune = pyodbc.connect(CONN_STRING)
        cursor = conexiune.cursor()

        # 1. INSERARE STAPAN (STAPANID este generat automat)
        cursor.execute(
            """
            INSERT INTO STAPAN (Nume, Prenume, Telefon, Addresa)
            VALUES (?, ?, ?, ?, ?)
            """,
            (owner_last_name, owner_first_name, telephone, address),
        )
        # EXTRAGE ID-ul generat pentru STAPAN
        cursor.execute("SELECT SCOPE_IDENTITY()")
        stapan_id_generat = cursor.fetchone()[0]

        # 2. INSERARE ANIMAL (ANIMALID este generat automat)
        cursor.execute(
            """
            INSERT INTO Animal
            (Nume, Specie, Rasa, Varsta, Sex)
            VALUES (?, ?, ?, ?, ?)""",
            (pet_name, species, breed, age, sex),
        )
        # EXTRAGE ID-ul generat pentru ANIMAL
        cursor.execute("SELECT SCOPE_IDENTITY()")
        animal_id_generat = cursor.fetchone()[0]

        # 3. INSERARE FISA MEDICALA
        # Foloseste ID-urile generate (stapan_id_generat, animal_id_generat)
        # si ID-ul utilizatorului logat (user_id)
        cursor.execute(
            """
            INSERT INTO FISA_MEDICALA (Id_stapan, Id_animal, Id_user)
            VALUES (?, ?, ?)
            """,
            (stapan_id_generat, animal_id_generat, user_id),
        )

        conexiune.commit()
        conexiune.close()
        fl.flash("SUCCESS: Save Info Successfully")
        return fl.redirect("http://cabinet-veterinar-pet.local/")
    except pyodbc.Error as ex:
        print(f"BD error: {ex}", file=sys.stderr)
        return (
            """BD error: Server error saving information. Make sure 
            all IDs were generated correctly""",
            500,
        )


@app.route("/")
def show_register_page():
    # Va afișa conținutul din noul fișier 'register.html'
    return fl.render_template("register.html")


# --- RUTA PENTRU AFIȘAREA PAGINII DE AUTENTIFICARE ---
@app.route("/login-page")
def show_login_page():
    # Va afișa conținutul din noul fișier 'login.html'
    return fl.render_template("login.html")


@app.route("/save-programare")
def show_save_programare_page():
    if "user_id" not in fl.session:
        # 2. Dacă NU este logat, redirecționează la pagina de logare
        # Redirectionam catre ruta '/login-page', care randeaza 'login.html'
        return fl.redirect(fl.url_for("show_login_page"))
    return fl.render_template("formularprogramare.html")


if __name__ == "__main__":
    # Asigură-te că rulezi 'pip install flask' înainte
    app.run(debug=True)
