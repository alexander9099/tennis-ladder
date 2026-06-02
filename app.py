import os
import re
from datetime import datetime, timezone
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

CHALLENGE_RANGE        = 5    # positions either side you can challenge
MAX_OUTGOING           = 2    # max simultaneous outgoing challenges
RESPOND_DAYS           = 3    # days to accept/decline before forfeit
PLAY_DAYS              = 10   # days to play after accepting
INACTIVITY_DAYS        = 30   # days without a match before penalty
INACTIVITY_DROP        = 10   # positions dropped for inactivity
WILDCARD_EVERY         = 3    # earn a wildcard every N matches
AVAILABILITY_RETURN_DROP = 3  # positions dropped when returning from unavailability


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
    """Thin shim making psycopg2 chainable like sqlite3 (conn.execute().fetchone())."""
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
        raise RuntimeError("DATABASE_URL is not set.")
    return _Conn(psycopg2.connect(DATABASE_URL,
                                  cursor_factory=psycopg2.extras.RealDictCursor))


# ── Schema & seeding ───────────────────────────────────────────────────────────

def init_db():
    conn = get_db()

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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            id               SERIAL PRIMARY KEY,
            challenger_id    INTEGER NOT NULL REFERENCES players(id),
            challenged_id    INTEGER NOT NULL REFERENCES players(id),
            status           TEXT NOT NULL DEFAULT 'pending',
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            responded_at     TIMESTAMPTZ,
            deadline_respond TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '3 days',
            deadline_play    TIMESTAMPTZ,
            match_id         INTEGER REFERENCES matches(id)
        )
    """)
    conn.execute(
        "ALTER TABLE challenges ADD COLUMN IF NOT EXISTS match_id INTEGER REFERENCES matches(id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chal_challenger ON challenges(challenger_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chal_challenged ON challenges(challenged_id)"
    )

    conn.execute("ALTER TABLE players ADD COLUMN IF NOT EXISTS wildcard_available BOOLEAN DEFAULT TRUE")
    conn.execute("ALTER TABLE players ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ DEFAULT NOW()")
    conn.execute("ALTER TABLE players ADD COLUMN IF NOT EXISTS is_available BOOLEAN DEFAULT TRUE")
    conn.execute("ALTER TABLE players ADD COLUMN IF NOT EXISTS is_on_ladder BOOLEAN DEFAULT TRUE")
    conn.execute("ALTER TABLE challenges ADD COLUMN IF NOT EXISTS is_wildcard BOOLEAN DEFAULT FALSE")
    conn.execute("ALTER TABLE challenges ADD COLUMN IF NOT EXISTS remind_respond_sent BOOLEAN DEFAULT FALSE")
    conn.execute("ALTER TABLE challenges ADD COLUMN IF NOT EXISTS remind_play_sent BOOLEAN DEFAULT FALSE")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS season_archives (
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            standings   TEXT NOT NULL
        )
    """)
    # Sync wildcard status with actual match counts for existing players
    conn.execute("UPDATE players SET wildcard_available = ((wins + losses) %% 3 = 0)")

    # Seed admin
    if conn.execute(
        "SELECT COUNT(*) AS n FROM users WHERE username = 'admin'"
    ).fetchone()["n"] == 0:
        admin_pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        conn.execute(
            "INSERT INTO users (username, email, password_hash, player_id, is_admin) "
            "VALUES ('admin', 'admin@localhost', %s, NULL, 1)",
            (hash_password(admin_pw),),
        )
        print(f"⚠️  Admin created — username: admin  password: {admin_pw}")

    conn.commit()
    conn.close()


# ── Email ──────────────────────────────────────────────────────────────────────

def send_challenge_email(to_email: str, to_name: str, challenger_name: str, base_url: str):
    """Notify challenged player via SendGrid. Silent no-op if API key not set."""
    api_key   = os.environ.get("SENDGRID_API_KEY")
    from_addr = os.environ.get("FROM_EMAIL", "noreply@example.com")

    if not api_key:
        app.logger.info(f"[email] No SENDGRID_API_KEY — skipping notification to {to_email}")
        return

    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
      <div style="background:#166534;padding:20px 24px;border-radius:12px 12px 0 0;">
        <h1 style="color:white;margin:0;font-size:20px;">🎾 OA Summer Tennis Ladder</h1>
      </div>
      <div style="background:#ffffff;padding:28px 24px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 12px 12px;">
        <p style="margin:0 0 12px;color:#111827;">Hi <strong>{to_name}</strong>,</p>
        <p style="margin:0 0 20px;color:#374151;">
          <strong>{challenger_name}</strong> has challenged you on the OA Summer Tennis Ladder.
          You have <strong>{RESPOND_DAYS} days</strong> to accept or decline —
          if you don't respond the match will be awarded to your challenger.
        </p>
        <a href="{base_url}challenges"
           style="display:inline-block;background:#166534;color:white;text-decoration:none;
                  padding:12px 28px;border-radius:8px;font-weight:600;font-size:15px;">
          View &amp; Respond →
        </a>
        <p style="margin:24px 0 0;color:#9ca3af;font-size:12px;">
          You're receiving this because your account is registered on OA Summer Tennis Ladder.
        </p>
      </div>
    </div>
    """
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helper.mail import Mail as SGMail
        msg = SGMail(
            from_email=from_addr,
            to_emails=to_email,
            subject=f"🎾 {challenger_name} has challenged you on the OA Summer Tennis Ladder",
            html_content=html,
        )
        SendGridAPIClient(api_key).send(msg)
    except Exception as exc:
        app.logger.error(f"SendGrid error: {exc}")


# ── Reminder emails ───────────────────────────────────────────────────────────

def send_reminder_email(to_email: str, to_name: str, subject: str, body_html: str):
    """Send a deadline reminder via SendGrid. Silent no-op if API key not set."""
    api_key   = os.environ.get("SENDGRID_API_KEY")
    from_addr = os.environ.get("FROM_EMAIL", "noreply@example.com")
    if not api_key:
        app.logger.info(f"[email] No SENDGRID_API_KEY — skipping reminder to {to_email}")
        return
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helper.mail import Mail as SGMail
        msg = SGMail(from_email=from_addr, to_emails=to_email,
                     subject=subject, html_content=body_html)
        SendGridAPIClient(api_key).send(msg)
    except Exception as exc:
        app.logger.error(f"SendGrid error: {exc}")


def send_deadline_reminders(conn: _Conn):
    """Send 24-hour warning emails for approaching challenge deadlines."""
    base_url = os.environ.get("APP_BASE_URL", "http://localhost:5000/")
    if not base_url.endswith("/"):
        base_url += "/"

    # ── Response deadline: notify the challenged player ────────────────────────
    resp_due = conn.execute("""
        SELECT c.id, cp.name AS challenger_name,
               u.email AS to_email, u.username AS to_username
        FROM challenges c
        JOIN players cp ON cp.id = c.challenger_id
        LEFT JOIN users u ON u.player_id = c.challenged_id
        WHERE c.status = 'pending'
          AND c.deadline_respond BETWEEN NOW() AND NOW() + INTERVAL '24 hours'
          AND c.remind_respond_sent = FALSE
          AND u.email IS NOT NULL
    """).fetchall()

    for r in resp_due:
        html = f"""
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
          <div style="background:#166534;padding:20px 24px;border-radius:12px 12px 0 0;">
            <h1 style="color:white;margin:0;font-size:20px;">🎾 OA Summer Tennis Ladder</h1>
          </div>
          <div style="background:#ffffff;padding:28px 24px;border:1px solid #e5e7eb;
                      border-top:none;border-radius:0 0 12px 12px;">
            <p style="margin:0 0 12px;color:#111827;">Hi <strong>{r['to_username']}</strong>,</p>
            <p style="margin:0 0 20px;color:#374151;">
              Reminder: <strong>{r['challenger_name']}</strong> has challenged you and you have
              less than 24 hours to respond. If you don't respond the match will be awarded
              to your challenger as a walkover.
            </p>
            <a href="{base_url}challenges"
               style="display:inline-block;background:#166534;color:white;text-decoration:none;
                      padding:12px 28px;border-radius:8px;font-weight:600;font-size:15px;">
              Respond Now →
            </a>
          </div>
        </div>
        """
        send_reminder_email(
            r["to_email"], r["to_username"],
            f"⏰ Reminder: respond to {r['challenger_name']}'s challenge before it expires",
            html,
        )
        conn.execute(
            "UPDATE challenges SET remind_respond_sent = TRUE WHERE id = %s", (r["id"],)
        )

    # ── Play deadline: notify both players ─────────────────────────────────────
    play_due = conn.execute("""
        SELECT c.id,
               pc.name AS challenger_name, pp.name AS challenged_name,
               uc.email AS challenger_email, uc.username AS challenger_username,
               up.email AS challenged_email, up.username AS challenged_username
        FROM challenges c
        JOIN players pc ON pc.id = c.challenger_id
        JOIN players pp ON pp.id = c.challenged_id
        LEFT JOIN users uc ON uc.player_id = c.challenger_id
        LEFT JOIN users up ON up.player_id = c.challenged_id
        WHERE c.status = 'accepted'
          AND c.deadline_play BETWEEN NOW() AND NOW() + INTERVAL '24 hours'
          AND c.remind_play_sent = FALSE
    """).fetchall()

    for r in play_due:
        for (email, username, opponent) in [
            (r["challenger_email"], r["challenger_username"], r["challenged_name"]),
            (r["challenged_email"], r["challenged_username"], r["challenger_name"]),
        ]:
            if not email:
                continue
            html = f"""
            <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
              <div style="background:#166534;padding:20px 24px;border-radius:12px 12px 0 0;">
                <h1 style="color:white;margin:0;font-size:20px;">🎾 OA Summer Tennis Ladder</h1>
              </div>
              <div style="background:#ffffff;padding:28px 24px;border:1px solid #e5e7eb;
                          border-top:none;border-radius:0 0 12px 12px;">
                <p style="margin:0 0 12px;color:#111827;">Hi <strong>{username}</strong>,</p>
                <p style="margin:0 0 20px;color:#374151;">
                  Reminder: you have less than 24 hours to play your match against
                  <strong>{opponent}</strong>. Submit the result before the deadline —
                  if the match isn't played in time the challenge will expire with no
                  position change.
                </p>
                <a href="{base_url}submit"
                   style="display:inline-block;background:#166534;color:white;text-decoration:none;
                          padding:12px 28px;border-radius:8px;font-weight:600;font-size:15px;">
                  Submit Result →
                </a>
              </div>
            </div>
            """
            send_reminder_email(
                email, username,
                f"⏰ Reminder: play your match against {opponent} before it expires",
                html,
            )
        conn.execute(
            "UPDATE challenges SET remind_play_sent = TRUE WHERE id = %s", (r["id"],)
        )

    if resp_due or play_due:
        conn.commit()


# ── Ladder logic ───────────────────────────────────────────────────────────────

def update_ladder(conn: _Conn, winner_id: int, loser_id: int):
    """Promote winner to loser's spot when winner is currently ranked lower."""
    winner = conn.execute("SELECT position FROM players WHERE id = %s", (winner_id,)).fetchone()
    loser  = conn.execute("SELECT position FROM players WHERE id = %s", (loser_id,)).fetchone()
    w_pos, l_pos = winner["position"], loser["position"]
    if w_pos <= l_pos:
        return
    conn.execute(
        "UPDATE players SET prev_position = position WHERE position >= %s AND position <= %s",
        (l_pos, w_pos),
    )
    conn.execute(
        "UPDATE players SET position = position + 1 WHERE position >= %s AND position < %s",
        (l_pos, w_pos),
    )
    conn.execute("UPDATE players SET position = %s WHERE id = %s", (l_pos, winner_id))


# ── Inactivity & wildcard helpers ─────────────────────────────────────────────

def drop_player_places(conn: _Conn, player_id: int, places: int):
    """Move a player down the ladder by `places` positions (inactivity penalty)."""
    player = conn.execute("SELECT position FROM players WHERE id = %s", (player_id,)).fetchone()
    if not player:
        return
    max_pos = conn.execute("SELECT MAX(position) AS m FROM players WHERE is_on_ladder = TRUE").fetchone()["m"]
    old_pos = player["position"]
    new_pos = min(old_pos + places, max_pos)
    if new_pos == old_pos:
        return
    conn.execute(
        "UPDATE players SET prev_position = position WHERE position > %s AND position <= %s",
        (old_pos, new_pos),
    )
    conn.execute(
        "UPDATE players SET position = position - 1 WHERE position > %s AND position <= %s",
        (old_pos, new_pos),
    )
    conn.execute(
        "UPDATE players SET position = %s, prev_position = %s WHERE id = %s",
        (new_pos, old_pos, player_id),
    )


def update_wildcard(conn: _Conn, player_id: int):
    """Recalculate wildcard_available after a match is played."""
    row = conn.execute(
        "SELECT wins + losses AS total FROM players WHERE id = %s", (player_id,)
    ).fetchone()
    if not row:
        return
    total = row["total"]
    has_wildcard = (total > 0 and total % WILDCARD_EVERY == 0)
    conn.execute(
        "UPDATE players SET wildcard_available = %s WHERE id = %s",
        (has_wildcard, player_id),
    )


def check_inactivity(conn: _Conn):
    """Drop players inactive for INACTIVITY_DAYS and reset their activity clock."""
    inactive = conn.execute("""
        SELECT id FROM players
        WHERE last_active_at < NOW() - INTERVAL '30 days'
          AND is_available = TRUE
          AND is_on_ladder = TRUE
    """).fetchall()
    for p in inactive:
        drop_player_places(conn, p["id"], INACTIVITY_DROP)
        conn.execute(
            "UPDATE players SET last_active_at = NOW() WHERE id = %s", (p["id"],)
        )
    if inactive:
        conn.commit()


# ── Challenge helpers ──────────────────────────────────────────────────────────

def expire_stale_challenges(conn: _Conn):
    """
    Pending past their 3-day response deadline → forfeit (challenger wins).
    Accepted past their 10-day play deadline   → expired (no position change).
    """
    # ── Forfeits: no response ──────────────────────────────────────────────────
    forfeits = conn.execute("""
        SELECT id, challenger_id, challenged_id FROM challenges
        WHERE status = 'pending' AND deadline_respond < NOW()
    """).fetchall()

    for ch in forfeits:
        update_ladder(conn, ch["challenger_id"], ch["challenged_id"])
        conn.execute("UPDATE players SET wins   = wins   + 1 WHERE id = %s", (ch["challenger_id"],))
        conn.execute("UPDATE players SET losses = losses + 1 WHERE id = %s", (ch["challenged_id"],))
        mid = conn.execute("""
            INSERT INTO matches (winner_id, loser_id, score, played_at)
            VALUES (%s, %s, 'Walkover (no response)', %s) RETURNING id
        """, (ch["challenger_id"], ch["challenged_id"],
              datetime.now().strftime("%Y-%m-%d %H:%M"))).fetchone()["id"]
        conn.execute(
            "UPDATE challenges SET status = 'forfeited', match_id = %s WHERE id = %s",
            (mid, ch["id"]),
        )

    # ── Expired: accepted but never played ────────────────────────────────────
    conn.execute("""
        UPDATE challenges SET status = 'expired'
        WHERE status = 'accepted' AND deadline_play < NOW()
    """)

    if forfeits:
        conn.commit()


def get_challenge_states(conn: _Conn, player_id: int, players: list, wildcard_available: bool = False) -> tuple:
    """
    Returns (state_dict, challenge_id_dict).
    state_dict      — player_id → state string
    challenge_id_dict — other_player_id → challenge_id for every active challenge I'm in
    """
    active = conn.execute("""
        SELECT id, challenger_id, challenged_id, status FROM challenges
        WHERE status IN ('pending', 'accepted')
    """).fetchall()

    occupied = {r["challenged_id"] for r in active}

    my_out = {r["challenged_id"]: r["status"]
              for r in active if r["challenger_id"] == player_id}
    my_in  = {r["challenger_id"]: r["status"]
              for r in active if r["challenged_id"] == player_id}

    # Map the OTHER player's id → challenge id (used by buttons in the template)
    challenge_ids = {}
    for r in active:
        if r["challenger_id"] == player_id:
            challenge_ids[r["challenged_id"]] = r["id"]
        elif r["challenged_id"] == player_id:
            challenge_ids[r["challenger_id"]] = r["id"]

    my_pos = next(p["position"] for p in players if p["id"] == player_id)
    outgoing_count = len(my_out)

    state = {}
    for p in players:
        pid = p["id"]
        if pid == player_id:
            state[pid] = "self"
            continue
        if pid in my_out:
            state[pid] = f"out_{my_out[pid]}"    # out_pending | out_accepted
            continue
        if pid in my_in:
            state[pid] = f"in_{my_in[pid]}"       # in_pending  | in_accepted
            continue
        if not p.get("is_available", True):
            state[pid] = "unavailable"
            continue
        out_of_range = abs(p["position"] - my_pos) > CHALLENGE_RANGE
        if out_of_range and not wildcard_available:
            state[pid] = "out_of_range"
            continue
        if pid in occupied:
            state[pid] = "ineligible"
            continue
        if outgoing_count >= MAX_OUTGOING:
            state[pid] = "maxed"
            continue
        state[pid] = "wildcard" if out_of_range else "available"

    return state, challenge_ids


# ── Context processor ──────────────────────────────────────────────────────────

@app.context_processor
def inject_pending_count():
    count = 0
    if current_user.is_authenticated and current_user.player_id:
        try:
            conn = get_db()
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM challenges WHERE challenged_id = %s AND status = 'pending'",
                (current_user.player_id,),
            ).fetchone()["n"]
            conn.close()
        except Exception:
            pass
    return {"pending_challenge_count": count}


# ── Routes: public ─────────────────────────────────────────────────────────────

@app.route("/ping")
def ping():
    from flask import jsonify
    return jsonify({"status": "ok"})

@app.route("/")
def index():
    conn = get_db()
    expire_stale_challenges(conn)
    check_inactivity(conn)
    send_deadline_reminders(conn)
    players = conn.execute(
        "SELECT * FROM players WHERE is_on_ladder = TRUE ORDER BY position"
    ).fetchall()

    challenge_state     = {}
    challenge_ids       = {}
    user_outgoing_count = 0
    user_has_wildcard   = False

    if current_user.is_authenticated and current_user.player_id:
        me = next((p for p in players if p["id"] == current_user.player_id), None)
        user_has_wildcard = bool(me["wildcard_available"]) if me else False
        challenge_state, challenge_ids = get_challenge_states(
            conn, current_user.player_id, players, user_has_wildcard
        )
        user_outgoing_count = conn.execute("""
            SELECT COUNT(*) AS n FROM challenges
            WHERE challenger_id = %s AND status IN ('pending', 'accepted')
        """, (current_user.player_id,)).fetchone()["n"]

    conn.close()
    return render_template("index.html",
                           players=players,
                           challenge_state=challenge_state,
                           challenge_ids=challenge_ids,
                           user_outgoing_count=user_outgoing_count,
                           user_has_wildcard=user_has_wildcard)


@app.route("/rules")
def rules():
    return render_template("rules.html")


@app.route("/history")
def history():
    conn = get_db()
    matches = conn.execute("""
        SELECT m.id, m.score, m.played_at,
               w.name AS winner_name, l.name AS loser_name,
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

        if not errors and conn.execute(
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
        row  = conn.execute("SELECT * FROM users WHERE username = %s", (username,)).fetchone()
        conn.close()
        if row and verify_password(password, row["password_hash"]):
            login_user(User(row), remember=bool(request.form.get("remember")))
            nxt = request.args.get("next", "")
            if nxt and nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
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

    # Non-admin players only see opponents they have an active challenge with
    if not current_user.is_admin and current_user.player_id:
        challenge_partners = conn.execute("""
            SELECT DISTINCT p.* FROM players p
            JOIN challenges c
              ON (c.challenger_id = %s AND c.challenged_id = p.id)
              OR (c.challenged_id = %s AND c.challenger_id = p.id)
            WHERE c.status IN ('pending', 'accepted')
            ORDER BY p.position
        """, (current_user.player_id, current_user.player_id)).fetchall()
    else:
        challenge_partners = all_players

    # Pre-populate from an accepted challenge link (?challenge=<id>)
    linked_challenge = None
    cid = request.args.get("challenge")
    if cid and current_user.player_id:
        linked_challenge = conn.execute("""
            SELECT c.*, pc.name AS challenger_name, pp.name AS challenged_name
            FROM challenges c
            JOIN players pc ON pc.id = c.challenger_id
            JOIN players pp ON pp.id = c.challenged_id
            WHERE c.id = %s AND c.status = 'accepted'
              AND (c.challenger_id = %s OR c.challenged_id = %s)
        """, (cid, current_user.player_id, current_user.player_id)).fetchone()

    if request.method == "POST":
        score = request.form.get("score", "").strip()

        if current_user.is_admin:
            winner_id = request.form.get("winner_id")
            loser_id  = request.form.get("loser_id")
        else:
            result      = request.form.get("result")
            opponent_id = request.form.get("opponent_id")
            winner_id, loser_id = (
                (str(current_user.player_id), opponent_id)
                if result == "win"
                else (opponent_id, str(current_user.player_id))
            )

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
            return render_template("submit_match.html",
                                   all_players=all_players,
                                   challenge_partners=challenge_partners,
                                   linked_challenge=linked_challenge)

        update_ladder(conn, int(winner_id), int(loser_id))
        conn.execute("UPDATE players SET wins   = wins   + 1 WHERE id = %s", (winner_id,))
        conn.execute("UPDATE players SET losses = losses + 1 WHERE id = %s", (loser_id,))

        match_id = conn.execute("""
            INSERT INTO matches (winner_id, loser_id, score, played_at, submitted_by)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
        """, (winner_id, loser_id, score,
              datetime.now().strftime("%Y-%m-%d %H:%M"), current_user.id)).fetchone()["id"]

        # Auto-close any active challenge between these two players
        conn.execute("""
            UPDATE challenges SET status = 'completed', match_id = %s
            WHERE status IN ('pending', 'accepted')
              AND ((challenger_id = %s AND challenged_id = %s)
                OR (challenger_id = %s AND challenged_id = %s))
        """, (match_id, winner_id, loser_id, loser_id, winner_id))

        update_wildcard(conn, int(winner_id))
        update_wildcard(conn, int(loser_id))
        conn.execute(
            "UPDATE players SET last_active_at = NOW() WHERE id = %s OR id = %s",
            (int(winner_id), int(loser_id)),
        )
        conn.commit()
        conn.close()
        flash("Match result recorded!", "success")
        return redirect(url_for("index"))

    conn.close()
    return render_template("submit_match.html",
                           all_players=all_players,
                           linked_challenge=linked_challenge)


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
        conn.close(); abort(404)

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
        conn.close(); abort(404)

    conn.execute(
        "UPDATE players SET wins   = GREATEST(0, wins   - 1) WHERE id = %s", (match["winner_id"],)
    )
    conn.execute(
        "UPDATE players SET losses = GREATEST(0, losses - 1) WHERE id = %s", (match["loser_id"],)
    )
    conn.execute("DELETE FROM matches WHERE id = %s", (match_id,))
    conn.commit()
    conn.close()
    flash("Match deleted. Win/loss counts adjusted; ladder positions are unchanged.", "success")
    return redirect(url_for("history"))


# ── Routes: challenge system ───────────────────────────────────────────────────

@app.route("/challenges")
@login_required
def challenges():
    if not current_user.player_id:
        flash("Your account isn't linked to a player profile.", "error")
        return redirect(url_for("index"))

    conn = get_db()
    expire_stale_challenges(conn)
    pid = current_user.player_id

    incoming = conn.execute("""
        SELECT c.*, pc.name AS challenger_name, pp.name AS challenged_name
        FROM challenges c
        JOIN players pc ON pc.id = c.challenger_id
        JOIN players pp ON pp.id = c.challenged_id
        WHERE c.challenged_id = %s
        ORDER BY c.created_at DESC
    """, (pid,)).fetchall()

    outgoing = conn.execute("""
        SELECT c.*, pc.name AS challenger_name, pp.name AS challenged_name
        FROM challenges c
        JOIN players pc ON pc.id = c.challenger_id
        JOIN players pp ON pp.id = c.challenged_id
        WHERE c.challenger_id = %s
        ORDER BY c.created_at DESC
    """, (pid,)).fetchall()

    conn.close()
    now = datetime.now(timezone.utc)
    return render_template("challenges.html", incoming=incoming, outgoing=outgoing, now=now)


@app.route("/challenge/<int:player_id>", methods=["POST"])
@login_required
def send_challenge(player_id):
    if not current_user.player_id:
        flash("Your account isn't linked to a player profile.", "error")
        return redirect(url_for("index"))

    conn = get_db()
    me     = conn.execute("SELECT * FROM players WHERE id = %s", (current_user.player_id,)).fetchone()
    target = conn.execute("SELECT * FROM players WHERE id = %s", (player_id,)).fetchone()

    if not target or player_id == current_user.player_id:
        conn.close()
        flash("Invalid challenge target.", "error")
        return redirect(url_for("index"))

    if not target["is_available"]:
        conn.close()
        flash(f"{target['name']} is currently unavailable and cannot be challenged.", "error")
        return redirect(url_for("index"))

    is_wildcard = False
    if abs(me["position"] - target["position"]) > CHALLENGE_RANGE:
        if not me["wildcard_available"]:
            conn.close()
            flash(f"You can only challenge players within {CHALLENGE_RANGE} positions of you.", "error")
            return redirect(url_for("index"))
        is_wildcard = True

    if conn.execute("""
        SELECT id FROM challenges
        WHERE challenged_id = %s AND status IN ('pending', 'accepted')
    """, (player_id,)).fetchone():
        conn.close()
        flash(f"{target['name']} is already being challenged.", "error")
        return redirect(url_for("index"))

    if conn.execute("""
        SELECT id FROM challenges
        WHERE challenger_id = %s AND challenged_id = %s AND status IN ('pending', 'accepted')
    """, (current_user.player_id, player_id)).fetchone():
        conn.close()
        flash("You already have an active challenge against that player.", "error")
        return redirect(url_for("index"))

    outgoing = conn.execute("""
        SELECT COUNT(*) AS n FROM challenges
        WHERE challenger_id = %s AND status IN ('pending', 'accepted')
    """, (current_user.player_id,)).fetchone()["n"]

    if outgoing >= MAX_OUTGOING:
        conn.close()
        flash(f"You already have {MAX_OUTGOING} active challenges. "
              "Wait for one to finish before sending another.", "error")
        return redirect(url_for("index"))

    conn.execute(
        "INSERT INTO challenges (challenger_id, challenged_id, is_wildcard) VALUES (%s, %s, %s)",
        (current_user.player_id, player_id, is_wildcard),
    )

    # Fetch the challenged player's email for notification
    target_user = conn.execute(
        "SELECT email, username FROM users WHERE player_id = %s", (player_id,)
    ).fetchone()

    conn.commit()
    conn.close()

    if target_user:
        send_challenge_email(
            to_email=target_user["email"],
            to_name=target_user["username"],
            challenger_name=me["name"],
            base_url=request.host_url,
        )

    if is_wildcard:
        flash(f"⚡ Wildcard challenge sent to {target['name']}! They have {RESPOND_DAYS} days to respond.", "success")
    else:
        flash(f"Challenge sent to {target['name']}! They have {RESPOND_DAYS} days to respond.", "success")
    return redirect(url_for("index"))


@app.route("/challenge/<int:challenge_id>/accept", methods=["POST"])
@login_required
def accept_challenge(challenge_id):
    if not current_user.player_id:
        return redirect(url_for("index"))

    conn = get_db()
    ch = conn.execute("""
        SELECT c.*, p.name AS challenger_name
        FROM challenges c JOIN players p ON p.id = c.challenger_id
        WHERE c.id = %s
    """, (challenge_id,)).fetchone()

    if not ch or ch["challenged_id"] != current_user.player_id:
        conn.close(); flash("Challenge not found.", "error"); return redirect(url_for("challenges"))
    if ch["status"] != "pending":
        conn.close(); flash("This challenge is no longer pending.", "error"); return redirect(url_for("challenges"))

    conn.execute("""
        UPDATE challenges
        SET status = 'accepted', responded_at = NOW(),
            deadline_play = NOW() + INTERVAL '10 days'
        WHERE id = %s
    """, (challenge_id,))
    conn.commit()
    conn.close()
    flash(f"Challenge accepted! You have {PLAY_DAYS} days to play {ch['challenger_name']}.", "success")
    return redirect(url_for("challenges"))


@app.route("/challenge/<int:challenge_id>/decline", methods=["POST"])
@login_required
def decline_challenge(challenge_id):
    if not current_user.player_id:
        return redirect(url_for("index"))

    conn = get_db()
    ch = conn.execute("""
        SELECT c.*, p.name AS challenger_name
        FROM challenges c JOIN players p ON p.id = c.challenger_id
        WHERE c.id = %s
    """, (challenge_id,)).fetchone()

    if not ch or ch["challenged_id"] != current_user.player_id:
        conn.close(); flash("Challenge not found.", "error"); return redirect(url_for("challenges"))
    if ch["status"] != "pending":
        conn.close(); flash("This challenge is no longer pending.", "error"); return redirect(url_for("challenges"))

    conn.execute(
        "UPDATE challenges SET status = 'declined', responded_at = NOW() WHERE id = %s",
        (challenge_id,),
    )
    conn.commit()
    conn.close()
    flash("Challenge declined.", "success")
    return redirect(url_for("challenges"))


@app.route("/challenge/<int:challenge_id>/cancel", methods=["POST"])
@login_required
def cancel_challenge(challenge_id):
    if not current_user.player_id:
        return redirect(url_for("index"))

    conn = get_db()
    ch = conn.execute("SELECT * FROM challenges WHERE id = %s", (challenge_id,)).fetchone()

    if not ch or ch["challenger_id"] != current_user.player_id:
        conn.close(); flash("Challenge not found.", "error"); return redirect(url_for("challenges"))
    if ch["status"] != "pending":
        conn.close(); flash("Only pending challenges can be cancelled.", "error"); return redirect(url_for("challenges"))

    conn.execute(
        "UPDATE challenges SET status = 'cancelled' WHERE id = %s", (challenge_id,)
    )
    conn.commit()
    conn.close()
    flash("Challenge cancelled.", "success")
    return redirect(url_for("challenges"))


# ── Routes: player profiles ───────────────────────────────────────────────────

@app.route("/player/<int:player_id>")
@login_required
def player_profile(player_id):
    conn = get_db()
    player = conn.execute("SELECT * FROM players WHERE id = %s", (player_id,)).fetchone()
    if not player:
        conn.close(); abort(404)

    matches = conn.execute("""
        SELECT m.score, m.played_at,
               w.name AS winner_name, w.id AS winner_id,
               l.name AS loser_name,  l.id AS loser_id
        FROM matches m
        JOIN players w ON w.id = m.winner_id
        JOIN players l ON l.id = m.loser_id
        WHERE m.winner_id = %s OR m.loser_id = %s
        ORDER BY m.id DESC
    """, (player_id, player_id)).fetchall()

    conn.close()
    return render_template("player_profile.html", player=player, matches=matches)


# ── Routes: admin panel ───────────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin_panel():
    conn = get_db()
    expire_stale_challenges(conn)
    check_inactivity(conn)
    send_deadline_reminders(conn)

    warning_players = conn.execute("""
        SELECT id, name, position, last_active_at,
               EXTRACT(DAY FROM NOW() - last_active_at)::int AS days_inactive
        FROM players
        WHERE is_available = TRUE AND is_on_ladder = TRUE
          AND last_active_at < NOW() - INTERVAL '15 days'
        ORDER BY last_active_at ASC
    """).fetchall()

    all_players = conn.execute(
        "SELECT * FROM players ORDER BY is_on_ladder DESC NULLS LAST, position NULLS LAST, name"
    ).fetchall()

    active_challenges = conn.execute("""
        SELECT c.id, c.status, c.created_at,
               pc.name AS challenger_name, pp.name AS challenged_name
        FROM challenges c
        JOIN players pc ON pc.id = c.challenger_id
        JOIN players pp ON pp.id = c.challenged_id
        WHERE c.status IN ('pending', 'accepted')
        ORDER BY c.created_at ASC
    """).fetchall()

    archives = conn.execute(
        "SELECT id, name, archived_at FROM season_archives ORDER BY archived_at DESC"
    ).fetchall()

    conn.close()
    return render_template("admin.html",
                           warning_players=warning_players,
                           all_players=all_players,
                           active_challenges=active_challenges,
                           archives=archives)


@app.route("/admin/season-reset", methods=["POST"])
@admin_required
def season_reset():
    import json
    season_name = request.form.get("season_name", "").strip() or "Season"
    conn = get_db()

    players = conn.execute(
        "SELECT id, name, position, wins, losses FROM players ORDER BY position"
    ).fetchall()
    conn.execute(
        "INSERT INTO season_archives (name, standings) VALUES (%s, %s)",
        (season_name, json.dumps([dict(p) for p in players])),
    )
    conn.execute("DELETE FROM challenges")
    conn.execute("DELETE FROM matches")
    conn.execute("""
        UPDATE players
        SET wins = 0, losses = 0, prev_position = NULL,
            wildcard_available = TRUE, last_active_at = NOW()
    """)
    conn.commit()
    conn.close()
    flash(f"Season '{season_name}' archived. Stats and matches cleared for the new season.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/season/<int:archive_id>")
@admin_required
def season_archive(archive_id):
    import json
    conn = get_db()
    archive = conn.execute(
        "SELECT * FROM season_archives WHERE id = %s", (archive_id,)
    ).fetchone()
    if not archive:
        conn.close(); abort(404)
    standings = json.loads(archive["standings"])
    conn.close()
    return render_template("season_archive.html", archive=archive, standings=standings)


# ── Routes: availability & leave ladder ──────────────────────────────────────

@app.route("/player/set-availability", methods=["POST"])
@login_required
def set_availability():
    if not current_user.player_id:
        flash("Your account isn't linked to a player profile.", "error")
        return redirect(url_for("index"))

    make_available = request.form.get("available") == "1"
    conn = get_db()
    player = conn.execute(
        "SELECT * FROM players WHERE id = %s", (current_user.player_id,)
    ).fetchone()

    if not player or not player["is_on_ladder"]:
        conn.close()
        flash("Player not found.", "error")
        return redirect(url_for("index"))

    if make_available:
        drop_player_places(conn, current_user.player_id, AVAILABILITY_RETURN_DROP)
        conn.execute(
            "UPDATE players SET is_available = TRUE, last_active_at = NOW() WHERE id = %s",
            (current_user.player_id,),
        )
        conn.commit()
        conn.close()
        flash(f"You're back on the ladder. You've dropped {AVAILABILITY_RETURN_DROP} places from your current position.", "success")
    else:
        conn.execute("""
            UPDATE challenges SET status = 'cancelled'
            WHERE status IN ('pending', 'accepted')
              AND (challenger_id = %s OR challenged_id = %s)
        """, (current_user.player_id, current_user.player_id))
        conn.execute(
            "UPDATE players SET is_available = FALSE WHERE id = %s",
            (current_user.player_id,),
        )
        conn.commit()
        conn.close()
        flash("You're now marked as unavailable. Your active challenges have been cancelled.", "success")

    return redirect(url_for("player_profile", player_id=current_user.player_id))


@app.route("/player/leave", methods=["POST"])
@login_required
def leave_ladder():
    if not current_user.player_id:
        flash("Your account isn't linked to a player profile.", "error")
        return redirect(url_for("index"))

    conn = get_db()
    player = conn.execute(
        "SELECT * FROM players WHERE id = %s", (current_user.player_id,)
    ).fetchone()

    if not player or not player["is_on_ladder"]:
        conn.close()
        flash("You're not currently on the ladder.", "error")
        return redirect(url_for("player_profile", player_id=current_user.player_id))

    conn.execute("""
        UPDATE challenges SET status = 'cancelled'
        WHERE status IN ('pending', 'accepted')
          AND (challenger_id = %s OR challenged_id = %s)
    """, (current_user.player_id, current_user.player_id))

    old_pos = player["position"]
    conn.execute(
        "UPDATE players SET position = position - 1 WHERE position > %s AND is_on_ladder = TRUE",
        (old_pos,),
    )
    conn.execute(
        "UPDATE players SET is_on_ladder = FALSE, position = NULL WHERE id = %s",
        (current_user.player_id,),
    )
    conn.commit()
    conn.close()
    flash("You have left the ladder. Your match history is preserved. You can rejoin at any time.", "success")
    return redirect(url_for("player_profile", player_id=current_user.player_id))


@app.route("/player/rejoin", methods=["POST"])
@login_required
def rejoin_ladder():
    if not current_user.player_id:
        flash("Your account isn't linked to a player profile.", "error")
        return redirect(url_for("index"))

    conn = get_db()
    player = conn.execute(
        "SELECT * FROM players WHERE id = %s", (current_user.player_id,)
    ).fetchone()

    if not player or player["is_on_ladder"]:
        conn.close()
        flash("You're already on the ladder.", "error")
        return redirect(url_for("index"))

    max_pos = conn.execute(
        "SELECT COALESCE(MAX(position), 0) AS m FROM players WHERE is_on_ladder = TRUE"
    ).fetchone()["m"]

    conn.execute(
        "UPDATE players SET is_on_ladder = TRUE, is_available = TRUE, position = %s, "
        "last_active_at = NOW() WHERE id = %s",
        (max_pos + 1, current_user.player_id),
    )
    conn.commit()
    conn.close()
    flash("Welcome back! You've been added to the bottom of the ladder.", "success")
    return redirect(url_for("player_profile", player_id=current_user.player_id))


# ── Routes: admin player management ──────────────────────────────────────────

@app.route("/admin/player/<int:player_id>/set-availability", methods=["POST"])
@admin_required
def admin_set_availability(player_id):
    make_available = request.form.get("available") == "1"
    conn = get_db()
    player = conn.execute("SELECT * FROM players WHERE id = %s", (player_id,)).fetchone()

    if not player:
        conn.close()
        flash("Player not found.", "error")
        return redirect(url_for("admin_panel"))

    if make_available:
        if not player["is_available"] and player["is_on_ladder"]:
            drop_player_places(conn, player_id, AVAILABILITY_RETURN_DROP)
        conn.execute(
            "UPDATE players SET is_available = TRUE, last_active_at = NOW() WHERE id = %s",
            (player_id,),
        )
        conn.commit()
        conn.close()
        flash(f"{player['name']} is now available and has dropped {AVAILABILITY_RETURN_DROP} places.", "success")
    else:
        conn.execute("""
            UPDATE challenges SET status = 'cancelled'
            WHERE status IN ('pending', 'accepted')
              AND (challenger_id = %s OR challenged_id = %s)
        """, (player_id, player_id))
        conn.execute(
            "UPDATE players SET is_available = FALSE WHERE id = %s", (player_id,)
        )
        conn.commit()
        conn.close()
        flash(f"{player['name']} has been marked as unavailable.", "success")

    return redirect(url_for("admin_panel"))


@app.route("/admin/adjust-position", methods=["POST"])
@admin_required
def admin_adjust_position():
    player_id   = request.form.get("player_id", "").strip()
    new_pos_str = request.form.get("new_position", "").strip()

    if not player_id or not new_pos_str:
        flash("Please select a player and enter a position.", "error")
        return redirect(url_for("admin_panel"))

    try:
        new_pos = int(new_pos_str)
    except ValueError:
        flash("Position must be a number.", "error")
        return redirect(url_for("admin_panel"))

    conn = get_db()
    player = conn.execute(
        "SELECT * FROM players WHERE id = %s AND is_on_ladder = TRUE", (player_id,)
    ).fetchone()

    if not player:
        conn.close()
        flash("Player not found or not currently on the ladder.", "error")
        return redirect(url_for("admin_panel"))

    max_pos = conn.execute(
        "SELECT MAX(position) AS m FROM players WHERE is_on_ladder = TRUE"
    ).fetchone()["m"]
    new_pos = max(1, min(new_pos, max_pos))
    old_pos = player["position"]

    if new_pos == old_pos:
        conn.close()
        flash(f"{player['name']} is already at position #{old_pos}.", "success")
        return redirect(url_for("admin_panel"))

    pid = int(player_id)
    if new_pos < old_pos:
        conn.execute("""
            UPDATE players SET position = position + 1
            WHERE position >= %s AND position < %s AND id != %s AND is_on_ladder = TRUE
        """, (new_pos, old_pos, pid))
    else:
        conn.execute("""
            UPDATE players SET position = position - 1
            WHERE position > %s AND position <= %s AND id != %s AND is_on_ladder = TRUE
        """, (old_pos, new_pos, pid))

    conn.execute(
        "UPDATE players SET position = %s, prev_position = %s WHERE id = %s",
        (new_pos, old_pos, pid),
    )
    conn.commit()
    conn.close()
    flash(f"{player['name']} moved from #{old_pos} to #{new_pos}.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/player/<int:player_id>/delete", methods=["POST"])
@admin_required
def admin_delete_player(player_id):
    conn = get_db()
    player = conn.execute("SELECT * FROM players WHERE id = %s", (player_id,)).fetchone()

    if not player:
        conn.close()
        flash("Player not found.", "error")
        return redirect(url_for("admin_panel"))

    # Block delete if the player has any match history to protect data integrity
    match_count = conn.execute(
        "SELECT COUNT(*) AS n FROM matches WHERE winner_id = %s OR loser_id = %s",
        (player_id, player_id),
    ).fetchone()["n"]

    if match_count > 0:
        conn.close()
        flash(
            f"Cannot delete {player['name']} — they have match history. "
            "Use 'Mark Unavailable' to remove them from active play instead.",
            "error",
        )
        return redirect(url_for("admin_panel"))

    # Cancel any open challenges
    conn.execute("""
        UPDATE challenges SET status = 'cancelled'
        WHERE status IN ('pending', 'accepted')
          AND (challenger_id = %s OR challenged_id = %s)
    """, (player_id, player_id))

    # Close the position gap left by this player
    if player["is_on_ladder"] and player["position"]:
        conn.execute("""
            UPDATE players SET position = position - 1
            WHERE position > %s AND is_on_ladder = TRUE
        """, (player["position"],))

    # Remove all traces of the player
    conn.execute("DELETE FROM challenges WHERE challenger_id = %s OR challenged_id = %s", (player_id, player_id))
    conn.execute("DELETE FROM users WHERE player_id = %s", (player_id,))
    conn.execute("DELETE FROM players WHERE id = %s", (player_id,))

    conn.commit()
    conn.close()
    flash(f"{player['name']} has been permanently deleted from the ladder.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/player/<int:player_id>/rename", methods=["POST"])
@admin_required
def admin_rename_player(player_id):
    new_name = request.form.get("new_name", "").strip()

    if not new_name:
        flash("Name cannot be empty.", "error")
        return redirect(url_for("admin_panel"))

    conn = get_db()
    player = conn.execute("SELECT * FROM players WHERE id = %s", (player_id,)).fetchone()

    if not player:
        conn.close()
        flash("Player not found.", "error")
        return redirect(url_for("admin_panel"))

    existing = conn.execute(
        "SELECT id FROM players WHERE name = %s AND id != %s", (new_name, player_id)
    ).fetchone()

    if existing:
        conn.close()
        flash(f"A player named '{new_name}' already exists.", "error")
        return redirect(url_for("admin_panel"))

    conn.execute("UPDATE players SET name = %s WHERE id = %s", (new_name, player_id))
    conn.commit()
    conn.close()
    flash(f"Player renamed to '{new_name}'.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/challenge/<int:challenge_id>/cancel", methods=["POST"])
@admin_required
def admin_cancel_challenge(challenge_id):
    conn = get_db()
    challenge = conn.execute("""
        SELECT c.*, pc.name AS challenger_name, pp.name AS challenged_name
        FROM challenges c
        JOIN players pc ON pc.id = c.challenger_id
        JOIN players pp ON pp.id = c.challenged_id
        WHERE c.id = %s
    """, (challenge_id,)).fetchone()

    if not challenge:
        conn.close()
        flash("Challenge not found.", "error")
        return redirect(url_for("admin_panel"))

    if challenge["status"] not in ("pending", "accepted"):
        conn.close()
        flash("This challenge is no longer active.", "error")
        return redirect(url_for("admin_panel"))

    conn.execute(
        "UPDATE challenges SET status = 'cancelled' WHERE id = %s", (challenge_id,)
    )
    conn.commit()
    conn.close()
    flash(
        f"Challenge between {challenge['challenger_name']} and {challenge['challenged_name']} cancelled.",
        "success",
    )
    return redirect(url_for("admin_panel"))


# ── Startup ────────────────────────────────────────────────────────────────────

if DATABASE_URL:
    init_db()

if __name__ == "__main__":
    if not DATABASE_URL:
        init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
