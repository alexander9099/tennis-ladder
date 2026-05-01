import os
import re
from datetime import datetime
from functools import wraps

import bcrypt as _bcrypt
import psycopg2
import psycopg2.errors
import psycopg2.extras
from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

# Load .env in development (no-op if python-dotenv isn't installed or file missing)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DATABASE_URL = os.environ.get("DATABASE_URL")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-secret-change-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access that page."
login_manager.login_message_category = "error"


# ── Password helpers ───────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return _bcrypt.checkpw(password.encode(), hashed.encode())


# ── User model ─────────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id        = row["id"]
        self.username  = row["username"]
        self.email     = row["email"]
        self.player_id = row["player_id"]
        self.is_admin  = bool(row["is_admin"])


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None


# ── Decorators ─────────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


# ── DB connection ──────────────────────────────────────────────────────────────

class _Conn:
    """
    Thin shim that makes psycopg2 look like sqlite3 for simple execute chains.
    Lets us write conn.execute(sql, params).fetchone() throughout the codebase.
    """
    def __init__(self, pg_conn):
        self._c = pg_conn

    def execute(self, sql: str, params=()):
        cur = self._c.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):   self._c.commit()
    def rollback(self): self._c.rollback()
    def close(self):    self._c.close()


def get_db() -> _Conn:
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "Add it to your .env file (local) or Render environment variables (production)."
        )
    pg = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return _Conn(pg)


# ── Schema + seeding ───────────────────────────────────────────────────────────

def init_db():
    conn = get_db()

    # PostgreSQL: SERIAL = auto-increment integer PK; IF NOT EXISTS on ADD COLUMN is native
    conn.execute("""
        CREATE TABLE IF NOT EXISTS players (
            id            SERIAL PRIMARY KEY,
            name          TEXT NOT NULL UNIQUE,
            position      INTEGER NOT NULL,
            prev_position INTEGER,
            wins          INTEGER NOT NULL DEFAULT 0,
            losses        INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("ALTER TABLE players ADD COLUMN IF NOT EXISTS prev_position INTEGER")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            player_id     INTEGER UNIQUE REFERENCES players(id),
            is_admin      INTEGER NOT NULL DEFAULT 0,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS matches (
            id           SERIAL PRIMARY KEY,
            winner_id    INTEGER NOT NULL REFERENCES players(id),
            loser_id     INTEGER NOT NULL REFERENCES players(id),
            score        TEXT NOT NULL,
            played_at    TEXT NOT NULL,
            submitted_by INTEGER REFERENCES users(id)
        )
    """)
    conn.execute(
        "ALTER TABLE matches ADD COLUMN IF NOT EXISTS submitted_by INTEGER REFERENCES users(id)"
    )

    # Seed players
    if conn.execute("SELECT COUNT(*) AS cnt FROM players").fetchone()["cnt"] == 0:
        for pos, name in enumerate([
            "Alex Rodriguez", "Sarah Mitchell", "James Chen", "Emma Thompson",
            "Marcus Williams", "Olivia Davis", "Ryan Park", "Sophia Martinez",
        ], start=1):
            conn.execute(
                "INSERT INTO players (name, position) VALUES (%s, %s)", (name, pos)
            )

    # Seed admin account
    if conn.execute(
        "SELECT COUNT(*) AS cnt FROM users WHERE username = 'admin'"
    ).fetchone()["cnt"] == 0:
        admin_pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        conn.execute(
            "INSERT INTO users (username, email, password_hash, player_id, is_admin) "
            "VALUES ('admin', 'admin@localhost', %s, NULL, 1)",
            (hash_password(admin_pw),),
        )
        print(f"⚠️  Admin created — username: admin  password: {admin_pw}")

    conn.commit()
    conn.close()


# ── Ladder logic ───────────────────────────────────────────────────────────────

def update_ladder(conn: _Conn, winner_id: int, loser_id: int):
    """Promote winner to loser's spot when winner is currently ranked lower."""
    winner = conn.execute("SELECT position FROM players WHERE id = %s", (winner_id,)).fetchone()
    loser  = conn.execute("SELECT position FROM players WHERE id = %s", (loser_id,)).fetchone()

    w_pos, l_pos = winner["position"], loser["position"]
    if w_pos <= l_pos:
        return  # Already ranked higher — no change

    conn.execute(
        "UPDATE players SET prev_position = position WHERE position >= %s AND position <= %s",
        (l_pos, w_pos),
    )
    conn.execute(
        "UPDATE players SET position = position + 1 WHERE position >= %s AND position < %s",
        (l_pos, w_pos),
    )
    conn.execute("UPDATE players SET position = %s WHERE id = %s", (l_pos, winner_id))


# ── Routes: public ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    conn = get_db()
    players = conn.execute("SELECT * FROM players ORDER BY position").fetchall()
    conn.close()
    return render_template("index.html", players=players)


@app.route("/history")
def history():
    conn = get_db()
    matches = conn.execute("""
        SELECT
            m.id,
            m.score,
            m.played_at,
            w.name     AS winner_name,
            l.name     AS loser_name,
            u.username AS submitted_by
        FROM matches m
        JOIN  players w ON w.id = m.winner_id
        JOIN  players l ON l.id = m.loser_id
        LEFT JOIN users u ON u.id = m.submitted_by
        ORDER BY m.id DESC
    """).fetchall()
    conn.close()
    return render_template("history.html", matches=matches)


# ── Routes: auth ───────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    conn = get_db()
    free_players = conn.execute("""
        SELECT * FROM players
        WHERE id NOT IN (SELECT player_id FROM users WHERE player_id IS NOT NULL)
        ORDER BY position
    """).fetchall()

    if request.method == "POST":
        username      = request.form.get("username", "").strip()
        email         = request.form.get("email", "").strip().lower()
        password      = request.form.get("password", "")
        confirm       = request.form.get("confirm_password", "")
        player_choice = request.form.get("player_id", "new")

        errors = []
        if not re.match(r"^\w{3,30}$", username):
            errors.append("Username must be 3–30 characters (letters, digits, underscores).")
        if not email or "@" not in email:
            errors.append("Enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            if conn.execute(
                "SELECT id FROM users WHERE username = %s OR email = %s", (username, email)
            ).fetchone():
                errors.append("That username or email is already registered.")

        if errors:
            for msg in errors:
                flash(msg, "error")
            conn.close()
            return render_template("auth/register.html", free_players=free_players)

        player_id = None
        try:
            if username.lower() != "admin":
                if player_choice == "new":
                    max_pos = conn.execute(
                        "SELECT COALESCE(MAX(position), 0) AS mp FROM players"
                    ).fetchone()["mp"]
                    player_id = conn.execute(
                        "INSERT INTO players (name, position) VALUES (%s, %s) RETURNING id",
                        (username, max_pos + 1),
                    ).fetchone()["id"]
                else:
                    free_ids = {str(p["id"]) for p in free_players}
                    if player_choice in free_ids:
                        player_id = int(player_choice)
                    else:
                        conn.close()
                        flash("That player profile was just claimed — please choose another.", "error")
                        return redirect(url_for("register"))

            conn.execute(
                "INSERT INTO users (username, email, password_hash, player_id, is_admin) "
                "VALUES (%s, %s, %s, %s, 0)",
                (username, email, hash_password(password), player_id),
            )
            conn.commit()

        except psycopg2.IntegrityError:
            conn.rollback()
            conn.close()
            flash("That player profile was just claimed — please choose another.", "error")
            return redirect(url_for("register"))

        conn.close()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    conn.close()
    return render_template("auth/register.html", free_players=free_players)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username = %s", (username,)).fetchone()
        conn.close()

        if row and verify_password(password, row["password_hash"]):
            login_user(User(row), remember=bool(request.form.get("remember")))
            next_page = request.args.get("next", "")
            if next_page and next_page.startswith("/") and not next_page.startswith("//"):
                return redirect(next_page)
            return redirect(url_for("index"))

        flash("Invalid username or password.", "error")

    return render_template("auth/login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You've been logged out.", "success")
    return redirect(url_for("index"))


# ── Routes: match submission ───────────────────────────────────────────────────

@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit_match():
    conn = get_db()
    all_players = conn.execute("SELECT * FROM players ORDER BY position").fetchall()

    if request.method == "POST":
        score = request.form.get("score", "").strip()

        if current_user.is_admin:
            winner_id = request.form.get("winner_id")
            loser_id  = request.form.get("loser_id")
        else:
            result      = request.form.get("result")
            opponent_id = request.form.get("opponent_id")
            if result == "win":
                winner_id, loser_id = str(current_user.player_id), opponent_id
            else:
                winner_id, loser_id = opponent_id, str(current_user.player_id)

        errors = []
        if not winner_id or not loser_id or not score:
            errors.append("Please fill in all fields.")
        elif winner_id == loser_id:
            errors.append("Winner and loser must be different players.")

        if not errors and not current_user.is_admin:
            if current_user.player_id is None:
                errors.append("Your account isn't linked to a player profile.")
            elif str(current_user.player_id) not in (winner_id, loser_id):
                errors.append("You can only submit results for matches you played in.")

        if errors:
            for msg in errors:
                flash(msg, "error")
            conn.close()
            return render_template("submit_match.html", all_players=all_players)

        update_ladder(conn, int(winner_id), int(loser_id))
        conn.execute("UPDATE players SET wins   = wins   + 1 WHERE id = %s", (winner_id,))
        conn.execute("UPDATE players SET losses = losses + 1 WHERE id = %s", (loser_id,))
        conn.execute(
            "INSERT INTO matches (winner_id, loser_id, score, played_at, submitted_by) "
            "VALUES (%s, %s, %s, %s, %s)",
            (winner_id, loser_id, score,
             datetime.now().strftime("%Y-%m-%d %H:%M"), current_user.id),
        )
        conn.commit()
        conn.close()
        flash("Match result recorded!", "success")
        return redirect(url_for("index"))

    conn.close()
    return render_template("submit_match.html", all_players=all_players)


# ── Routes: admin match management ────────────────────────────────────────────

@app.route("/match/<int:match_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_match(match_id):
    conn = get_db()
    match = conn.execute("""
        SELECT m.*, w.name AS winner_name, l.name AS loser_name
        FROM matches m
        JOIN players w ON w.id = m.winner_id
        JOIN players l ON l.id = m.loser_id
        WHERE m.id = %s
    """, (match_id,)).fetchone()

    if not match:
        conn.close()
        abort(404)

    if request.method == "POST":
        new_score = request.form.get("score", "").strip()
        if not new_score:
            flash("Score cannot be empty.", "error")
        else:
            conn.execute("UPDATE matches SET score = %s WHERE id = %s", (new_score, match_id))
            conn.commit()
            conn.close()
            flash("Score updated.", "success")
            return redirect(url_for("history"))

    conn.close()
    return render_template("match_edit.html", match=match)


@app.route("/match/<int:match_id>/delete", methods=["POST"])
@admin_required
def delete_match(match_id):
    conn = get_db()
    match = conn.execute("SELECT * FROM matches WHERE id = %s", (match_id,)).fetchone()

    if not match:
        conn.close()
        abort(404)

    # GREATEST() is PostgreSQL's multi-arg max — not the aggregate MAX()
    conn.execute(
        "UPDATE players SET wins   = GREATEST(0, wins   - 1) WHERE id = %s",
        (match["winner_id"],),
    )
    conn.execute(
        "UPDATE players SET losses = GREATEST(0, losses - 1) WHERE id = %s",
        (match["loser_id"],),
    )
    conn.execute("DELETE FROM matches WHERE id = %s", (match_id,))
    conn.commit()
    conn.close()

    flash("Match deleted. Win/loss counts adjusted; ladder positions are unchanged.", "success")
    return redirect(url_for("history"))


# ── Startup ────────────────────────────────────────────────────────────────────
# init_db() is idempotent (CREATE IF NOT EXISTS + INSERT IF EMPTY).
# Called at module load so gunicorn workers initialise the schema on first boot.

if DATABASE_URL:
    init_db()

if __name__ == "__main__":
    if not DATABASE_URL:
        init_db()  # will raise a clear RuntimeError if DATABASE_URL is still missing
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
