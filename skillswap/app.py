import os
import re
from datetime import datetime

try:
    from dotenv import load_dotenv
except ImportError:  # Allows app startup even if python-dotenv is missing locally.
    def load_dotenv(*_args, **_kwargs):
        return False
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from sqlalchemy import UniqueConstraint, func, or_
from sqlalchemy.exc import IntegrityError


load_dotenv()


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_database_url(url):
    # Some platforms still provide postgres:// which SQLAlchemy 2 rejects.
    if url and url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


app = Flask(__name__)

APP_ENV = os.getenv("APP_ENV", os.getenv("FLASK_ENV", "development")).strip().lower()
IS_PRODUCTION = APP_ENV == "production"

app.config["SQLALCHEMY_DATABASE_URI"] = normalize_database_url(
    os.getenv("DATABASE_URL", "sqlite:///skill_swap.db")
)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JSON_SORT_KEYS"] = False
app.config["DEBUG"] = env_bool("FLASK_DEBUG", not IS_PRODUCTION)
app.config["TESTING"] = env_bool("TESTING", False)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
app.config["SESSION_COOKIE_SECURE"] = env_bool("SESSION_COOKIE_SECURE", IS_PRODUCTION)
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SECURE"] = env_bool("REMEMBER_COOKIE_SECURE", IS_PRODUCTION)
app.config["WTF_CSRF_ENABLED"] = env_bool("WTF_CSRF_ENABLED", True)
app.config["WTF_CSRF_TIME_LIMIT"] = env_int("WTF_CSRF_TIME_LIMIT", 3600)
app.config["APP_HOST"] = os.getenv("APP_HOST", "127.0.0.1")
app.config["APP_PORT"] = env_int("APP_PORT", 5000)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)

login_manager.login_view = "login_page"
login_manager.login_message = None

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VALID_AVAILABILITY = {"weekends", "evenings", "anytime"}
API_PREFIXES = ("/api/", "/skills/", "/swap_request", "/respond_swap")
CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
EXCLUDED_LOCATION_COUNTRY_CODES = {"PK", "BD"}
VALID_SUPPORT_CATEGORIES = {
    "bug",
    "account_issue",
    "swap_issue",
    "report_user",
    "feature_request",
    "other",
}
VALID_SUPPORT_STATUSES = {"open", "in_progress", "resolved", "closed"}
ADMIN_EMAILS = {
    email.strip().casefold()
    for email in os.getenv("ADMIN_EMAILS", "").replace(";", ",").split(",")
    if email.strip()
}

# Starter global city dataset for autocomplete (PK and BD excluded by rule).
LOCATION_SUGGESTIONS = [
    {"city": "Ahmedabad", "country": "India", "country_code": "IN"},
    {"city": "Mumbai", "country": "India", "country_code": "IN"},
    {"city": "Delhi", "country": "India", "country_code": "IN"},
    {"city": "Bengaluru", "country": "India", "country_code": "IN"},
    {"city": "Hyderabad", "country": "India", "country_code": "IN"},
    {"city": "Pune", "country": "India", "country_code": "IN"},
    {"city": "Chennai", "country": "India", "country_code": "IN"},
    {"city": "Kolkata", "country": "India", "country_code": "IN"},
    {"city": "Jaipur", "country": "India", "country_code": "IN"},
    {"city": "Surat", "country": "India", "country_code": "IN"},
    {"city": "London", "country": "United Kingdom", "country_code": "GB"},
    {"city": "Manchester", "country": "United Kingdom", "country_code": "GB"},
    {"city": "Birmingham", "country": "United Kingdom", "country_code": "GB"},
    {"city": "New York", "country": "United States", "country_code": "US"},
    {"city": "Los Angeles", "country": "United States", "country_code": "US"},
    {"city": "Chicago", "country": "United States", "country_code": "US"},
    {"city": "San Francisco", "country": "United States", "country_code": "US"},
    {"city": "Seattle", "country": "United States", "country_code": "US"},
    {"city": "Austin", "country": "United States", "country_code": "US"},
    {"city": "Boston", "country": "United States", "country_code": "US"},
    {"city": "Toronto", "country": "Canada", "country_code": "CA"},
    {"city": "Vancouver", "country": "Canada", "country_code": "CA"},
    {"city": "Montreal", "country": "Canada", "country_code": "CA"},
    {"city": "Sydney", "country": "Australia", "country_code": "AU"},
    {"city": "Melbourne", "country": "Australia", "country_code": "AU"},
    {"city": "Brisbane", "country": "Australia", "country_code": "AU"},
    {"city": "Auckland", "country": "New Zealand", "country_code": "NZ"},
    {"city": "Singapore", "country": "Singapore", "country_code": "SG"},
    {"city": "Tokyo", "country": "Japan", "country_code": "JP"},
    {"city": "Osaka", "country": "Japan", "country_code": "JP"},
    {"city": "Seoul", "country": "South Korea", "country_code": "KR"},
    {"city": "Busan", "country": "South Korea", "country_code": "KR"},
    {"city": "Bangkok", "country": "Thailand", "country_code": "TH"},
    {"city": "Chiang Mai", "country": "Thailand", "country_code": "TH"},
    {"city": "Kuala Lumpur", "country": "Malaysia", "country_code": "MY"},
    {"city": "Jakarta", "country": "Indonesia", "country_code": "ID"},
    {"city": "Bali", "country": "Indonesia", "country_code": "ID"},
    {"city": "Manila", "country": "Philippines", "country_code": "PH"},
    {"city": "Dubai", "country": "United Arab Emirates", "country_code": "AE"},
    {"city": "Abu Dhabi", "country": "United Arab Emirates", "country_code": "AE"},
    {"city": "Riyadh", "country": "Saudi Arabia", "country_code": "SA"},
    {"city": "Jeddah", "country": "Saudi Arabia", "country_code": "SA"},
    {"city": "Doha", "country": "Qatar", "country_code": "QA"},
    {"city": "Muscat", "country": "Oman", "country_code": "OM"},
    {"city": "Kuwait City", "country": "Kuwait", "country_code": "KW"},
    {"city": "Istanbul", "country": "Turkey", "country_code": "TR"},
    {"city": "Ankara", "country": "Turkey", "country_code": "TR"},
    {"city": "Berlin", "country": "Germany", "country_code": "DE"},
    {"city": "Munich", "country": "Germany", "country_code": "DE"},
    {"city": "Hamburg", "country": "Germany", "country_code": "DE"},
    {"city": "Paris", "country": "France", "country_code": "FR"},
    {"city": "Lyon", "country": "France", "country_code": "FR"},
    {"city": "Marseille", "country": "France", "country_code": "FR"},
    {"city": "Madrid", "country": "Spain", "country_code": "ES"},
    {"city": "Barcelona", "country": "Spain", "country_code": "ES"},
    {"city": "Valencia", "country": "Spain", "country_code": "ES"},
    {"city": "Rome", "country": "Italy", "country_code": "IT"},
    {"city": "Milan", "country": "Italy", "country_code": "IT"},
    {"city": "Naples", "country": "Italy", "country_code": "IT"},
    {"city": "Amsterdam", "country": "Netherlands", "country_code": "NL"},
    {"city": "Rotterdam", "country": "Netherlands", "country_code": "NL"},
    {"city": "Brussels", "country": "Belgium", "country_code": "BE"},
    {"city": "Zurich", "country": "Switzerland", "country_code": "CH"},
    {"city": "Geneva", "country": "Switzerland", "country_code": "CH"},
    {"city": "Vienna", "country": "Austria", "country_code": "AT"},
    {"city": "Prague", "country": "Czech Republic", "country_code": "CZ"},
    {"city": "Warsaw", "country": "Poland", "country_code": "PL"},
    {"city": "Budapest", "country": "Hungary", "country_code": "HU"},
    {"city": "Athens", "country": "Greece", "country_code": "GR"},
    {"city": "Stockholm", "country": "Sweden", "country_code": "SE"},
    {"city": "Oslo", "country": "Norway", "country_code": "NO"},
    {"city": "Copenhagen", "country": "Denmark", "country_code": "DK"},
    {"city": "Helsinki", "country": "Finland", "country_code": "FI"},
    {"city": "Dublin", "country": "Ireland", "country_code": "IE"},
    {"city": "Lisbon", "country": "Portugal", "country_code": "PT"},
    {"city": "Moscow", "country": "Russia", "country_code": "RU"},
    {"city": "St Petersburg", "country": "Russia", "country_code": "RU"},
    {"city": "Kyiv", "country": "Ukraine", "country_code": "UA"},
    {"city": "Cape Town", "country": "South Africa", "country_code": "ZA"},
    {"city": "Johannesburg", "country": "South Africa", "country_code": "ZA"},
    {"city": "Nairobi", "country": "Kenya", "country_code": "KE"},
    {"city": "Lagos", "country": "Nigeria", "country_code": "NG"},
    {"city": "Accra", "country": "Ghana", "country_code": "GH"},
    {"city": "Cairo", "country": "Egypt", "country_code": "EG"},
    {"city": "Casablanca", "country": "Morocco", "country_code": "MA"},
    {"city": "Tunis", "country": "Tunisia", "country_code": "TN"},
    {"city": "Addis Ababa", "country": "Ethiopia", "country_code": "ET"},
    {"city": "São Paulo", "country": "Brazil", "country_code": "BR"},
    {"city": "Rio de Janeiro", "country": "Brazil", "country_code": "BR"},
    {"city": "Brasília", "country": "Brazil", "country_code": "BR"},
    {"city": "Buenos Aires", "country": "Argentina", "country_code": "AR"},
    {"city": "Santiago", "country": "Chile", "country_code": "CL"},
    {"city": "Lima", "country": "Peru", "country_code": "PE"},
    {"city": "Bogotá", "country": "Colombia", "country_code": "CO"},
    {"city": "Medellín", "country": "Colombia", "country_code": "CO"},
    {"city": "Mexico City", "country": "Mexico", "country_code": "MX"},
    {"city": "Guadalajara", "country": "Mexico", "country_code": "MX"},
    {"city": "Monterrey", "country": "Mexico", "country_code": "MX"},
]

BASE_SKILL_SUGGESTIONS = [
    "Python",
    "JavaScript",
    "React",
    "Node.js",
    "Digital Marketing",
    "SEO",
    "Content Writing",
    "Graphic Design",
    "Photoshop",
    "Canva",
    "Video Editing",
    "Public Speaking",
    "Excel Dashboards",
    "Data Analysis",
    "SQL",
    "UI/UX Design",
    "Figma",
    "Guitar",
    "Piano",
    "Singing",
    "Photography",
    "Social Media Strategy",
    "Machine Learning",
    "Power BI",
    "Communication Skills",
    "Resume Writing",
    "Interview Preparation",
    "Web Development",
    "Flask",
    "Django",
    "Java",
    "C++",
    "Leadership",
]


# ---------------- MODELS ----------------


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(100), nullable=True)
    availability = db.Column(db.String(20), nullable=True)
    is_public = db.Column(db.Boolean, default=True, nullable=False)

    skills = db.relationship("Skill", backref="user", cascade="all, delete-orphan", lazy=True)

    def __repr__(self):
        return f"<User id={self.id} email={self.email!r}>"


class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    skill_name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(10), nullable=False, index=True)  # offered / wanted

    def __repr__(self):
        return f"<Skill user_id={self.user_id} type={self.type!r} skill={self.skill_name!r}>"


class SwapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    requester = db.relationship("User", foreign_keys=[requester_id], lazy="joined")
    target = db.relationship("User", foreign_keys=[target_id], lazy="joined")

    def __repr__(self):
        return (
            f"<SwapRequest id={self.id} requester_id={self.requester_id} "
            f"target_id={self.target_id} status={self.status!r}>"
        )


class Connection(db.Model):
    __table_args__ = (
        UniqueConstraint("user1_id", "user2_id", name="uq_connection_pair"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    source_swap_request_id = db.Column(db.Integer, db.ForeignKey("swap_request.id"), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user1 = db.relationship("User", foreign_keys=[user1_id], lazy="joined")
    user2 = db.relationship("User", foreign_keys=[user2_id], lazy="joined")
    source_swap_request = db.relationship("SwapRequest", foreign_keys=[source_swap_request_id], lazy="joined")

    def __repr__(self):
        return f"<Connection id={self.id} pair=({self.user1_id}, {self.user2_id}) active={self.is_active}>"


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    connection_id = db.Column(db.Integer, db.ForeignKey("connection.id"), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    content = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False)

    connection = db.relationship("Connection", lazy="joined")
    sender = db.relationship("User", foreign_keys=[sender_id], lazy="joined")

    def __repr__(self):
        return f"<Message id={self.id} connection_id={self.connection_id} sender_id={self.sender_id}>"


class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    category = db.Column(db.String(30), nullable=False, default="other", index=True)
    subject = db.Column(db.String(120), nullable=False)
    related_skill = db.Column(db.String(100), nullable=True)
    related_location = db.Column(db.String(100), nullable=True)
    description = db.Column(db.String(2000), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id], lazy="joined")

    def __repr__(self):
        return f"<SupportTicket id={self.id} user_id={self.user_id} status={self.status!r}>"


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


@login_manager.unauthorized_handler
def unauthorized_handler():
    if request.path.startswith(API_PREFIXES):
        return jsonify({"message": "Authentication required."}), 401
    return redirect(url_for("login_page"))


@app.context_processor
def inject_template_helpers():
    return {
        "csrf_token": generate_csrf,
        "is_admin_viewer": current_user.is_authenticated and is_admin_user(current_user),
    }


@app.errorhandler(CSRFError)
def handle_csrf_error(_error):
    message = "CSRF token missing or invalid."
    if request.path.startswith(API_PREFIXES):
        return jsonify({"message": message}), 400
    if request.path == "/register":
        return render_template("register.html", error=message), 400
    return message, 400


# ---------------- HELPERS ----------------


def json_error(message, status=400):
    return jsonify({"message": message}), status


def clean_text(value, *, max_length=None, allow_blank=False):
    if value is None:
        return None

    text = str(value).strip()
    if not allow_blank and text == "":
        return None
    if max_length is not None:
        text = text[:max_length]
    return text


def is_admin_user(user):
    if not user or not getattr(user, "email", None):
        return False
    return user.email.strip().casefold() in ADMIN_EMAILS


def require_admin_access():
    if is_admin_user(current_user):
        return None
    if request.path.startswith("/api/"):
        return json_error("Admin access required.", 403)
    return redirect(url_for("home"))


def parse_positive_int(value, default, *, minimum=1, maximum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    if parsed < minimum:
        parsed = minimum
    if maximum is not None and parsed > maximum:
        parsed = maximum
    return parsed


def get_json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


def get_skill_value(user_id, skill_type):
    skill = Skill.query.filter_by(user_id=user_id, type=skill_type).first()
    return skill.skill_name if skill else ""


def set_skill_value(user_id, skill_type, skill_name):
    skill = Skill.query.filter_by(user_id=user_id, type=skill_type).first()
    if skill_name:
        if skill:
            skill.skill_name = skill_name
        else:
            db.session.add(Skill(user_id=user_id, type=skill_type, skill_name=skill_name))
    elif skill:
        db.session.delete(skill)


def user_skill_map(user_ids):
    if not user_ids:
        return {}

    rows = Skill.query.filter(Skill.user_id.in_(user_ids)).all()
    lookup = {user_id: {"offered": "", "wanted": ""} for user_id in user_ids}
    for row in rows:
        if row.type in {"offered", "wanted"}:
            lookup.setdefault(row.user_id, {"offered": "", "wanted": ""})[row.type] = row.skill_name
    return lookup


def has_configured_profile(user_id):
    offered = get_skill_value(user_id, "offered")
    wanted = get_skill_value(user_id, "wanted")
    return bool(offered and wanted)


def normalize_connection_pair(user_a_id, user_b_id):
    low, high = sorted([int(user_a_id), int(user_b_id)])
    return low, high


def get_connection_between_users(user_a_id, user_b_id):
    user1_id, user2_id = normalize_connection_pair(user_a_id, user_b_id)
    return Connection.query.filter_by(user1_id=user1_id, user2_id=user2_id, is_active=True).first()


def create_connection_if_missing(user_a_id, user_b_id, *, source_swap_request_id=None):
    if user_a_id == user_b_id:
        return None
    existing = get_connection_between_users(user_a_id, user_b_id)
    if existing:
        return existing

    user1_id, user2_id = normalize_connection_pair(user_a_id, user_b_id)
    connection = Connection(
        user1_id=user1_id,
        user2_id=user2_id,
        source_swap_request_id=source_swap_request_id,
        is_active=True,
    )
    db.session.add(connection)
    return connection


def user_is_connection_participant(connection, user_id):
    return connection and user_id in {connection.user1_id, connection.user2_id}


def get_other_connection_user(connection, user_id):
    if not connection:
        return None
    other_user_id = connection.user2_id if connection.user1_id == user_id else connection.user1_id
    return connection.user2 if connection.user2_id == other_user_id else connection.user1


def serialize_connection(connection, *, viewer_id=None, skill_lookup=None):
    viewer_id = viewer_id or current_user.id
    other_user = get_other_connection_user(connection, viewer_id)
    if not other_user:
        return None

    skill_lookup = skill_lookup or {}
    other_skills = skill_lookup.get(other_user.id, {"offered": "", "wanted": ""})
    latest_message = (
        Message.query.filter_by(connection_id=connection.id)
        .order_by(Message.created_at.desc())
        .first()
    )

    return {
        "id": connection.id,
        "created_at": connection.created_at.isoformat() if connection.created_at else None,
        "friend": {
            "id": other_user.id,
            "name": other_user.name,
            "location": other_user.location or "",
            "availability": other_user.availability or "",
        },
        "friend_skills": {
            "offered": other_skills.get("offered", ""),
            "wanted": other_skills.get("wanted", ""),
        },
        "latest_message": {
            "content": latest_message.content if latest_message else "",
            "sender_id": latest_message.sender_id if latest_message else None,
            "created_at": latest_message.created_at.isoformat() if latest_message and latest_message.created_at else None,
        },
    }


def serialize_message(message):
    return {
        "id": message.id,
        "connection_id": message.connection_id,
        "sender_id": message.sender_id,
        "sender_name": message.sender.name if message.sender else "",
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
        "is_read": bool(message.is_read),
    }


def serialize_support_ticket(ticket):
    return {
        "id": ticket.id,
        "category": ticket.category,
        "subject": ticket.subject,
        "related_skill": ticket.related_skill or "",
        "related_location": ticket.related_location or "",
        "description": ticket.description,
        "status": ticket.status,
        "created_at": ticket.created_at.isoformat() if ticket.created_at else None,
        "updated_at": ticket.updated_at.isoformat() if ticket.updated_at else None,
        "user": {
            "id": ticket.user.id,
            "name": ticket.user.name,
            "email": ticket.user.email,
        }
        if ticket.user
        else None,
    }


def get_current_user_connections():
    return Connection.query.filter(
        Connection.is_active.is_(True),
        or_(Connection.user1_id == current_user.id, Connection.user2_id == current_user.id),
    ).order_by(Connection.created_at.desc())


def _ranked_matches(query, term):
    normalized_term = term.casefold()

    def value_text(value):
        if isinstance(value, dict):
            raw = value.get("label") or value.get("value") or ""
            return str(raw)
        return str(value or "")

    def score_for(value):
        val = value_text(value).casefold()
        if val == normalized_term:
            return (0, len(val))
        if val.startswith(normalized_term):
            return (1, len(val))
        if normalized_term in val:
            return (2, len(val))
        return (9, len(val))

    return sorted(query, key=lambda item: score_for(item))


def location_suggestions(query_text, limit=8):
    term = clean_text(query_text, max_length=100)
    if not term or len(term) < 2:
        return []

    term_cf = term.casefold()
    matched = []
    seen = set()
    for item in LOCATION_SUGGESTIONS:
        if item["country_code"] in EXCLUDED_LOCATION_COUNTRY_CODES:
            continue
        label = f'{item["city"]}, {item["country"]}'
        if term_cf in label.casefold():
            if label.casefold() in seen:
                continue
            seen.add(label.casefold())
            matched.append(
                {
                    "value": item["city"],
                    "label": label,
                    "city": item["city"],
                    "country": item["country"],
                    "country_code": item["country_code"],
                }
            )
    matched = _ranked_matches(matched, term)
    return matched[:limit]


def skill_suggestions(query_text, limit=8):
    term = clean_text(query_text, max_length=100)
    if not term or len(term) < 1:
        return []

    term_cf = term.casefold()
    candidates = {skill.strip(): {"value": skill.strip(), "label": skill.strip()} for skill in BASE_SKILL_SUGGESTIONS}
    for row in Skill.query.with_entities(Skill.skill_name).distinct().limit(500).all():
        skill_name = (row[0] or "").strip()
        if skill_name:
            candidates.setdefault(skill_name, {"value": skill_name, "label": skill_name})

    filtered = [item for item in candidates.values() if term_cf in item["label"].casefold()]
    filtered = _ranked_matches(filtered, term)
    return filtered[:limit]


def get_trending_skills(limit=6):
    rows = (
        db.session.query(Skill.skill_name, func.count(Skill.id).label("count"))
        .join(User, Skill.user_id == User.id)
        .filter(Skill.type == "offered", User.is_public.is_(True))
        .group_by(Skill.skill_name)
        .order_by(func.count(Skill.id).desc(), Skill.skill_name.asc())
        .limit(limit)
        .all()
    )
    return [{"skill": skill_name, "count": count} for skill_name, count in rows]


def get_personalized_recommendations(user, limit=6):
    if not user or not getattr(user, "id", None):
        return []

    user_offered = (get_skill_value(user.id, "offered") or "").casefold()
    user_wanted = (get_skill_value(user.id, "wanted") or "").casefold()
    user_location = (user.location or "").casefold()
    user_availability = user.availability or ""

    rows = (
        db.session.query(Skill, User)
        .join(User, Skill.user_id == User.id)
        .filter(Skill.type == "offered", User.is_public.is_(True), User.id != user.id)
        .all()
    )

    recommendations = []
    for skill, other in rows:
        score = 0
        offered = (skill.skill_name or "").casefold()
        other_wanted = (get_skill_value(other.id, "wanted") or "").casefold()

        if user_wanted and (user_wanted in offered or offered in user_wanted):
            score += 5
        if user_offered and other_wanted and (user_offered in other_wanted or other_wanted in user_offered):
            score += 4
        if user_location and other.location and user_location in other.location.casefold():
            score += 2
        if user_availability and other.availability and user_availability == other.availability:
            score += 1

        recommendations.append(
            {
                "user_id": other.id,
                "name": other.name,
                "location": other.location or "",
                "availability": other.availability or "",
                "skill": skill.skill_name,
                "score": score,
            }
        )

    recommendations.sort(key=lambda item: (-item["score"], item["name"].lower(), item["skill"].lower()))
    deduped = []
    seen = set()
    for item in recommendations:
        key = (item["user_id"], item["skill"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= limit:
            break
    return deduped


def get_engagement_snapshot(user):
    if not user or not getattr(user, "id", None):
        return None

    friends_count = get_current_user_connections().count()
    pending_received = SwapRequest.query.filter_by(target_id=user.id, status="pending").count()
    open_tickets = SupportTicket.query.filter(
        SupportTicket.user_id == user.id,
        SupportTicket.status.in_(["open", "in_progress"]),
    ).count()
    return {
        "friends_count": friends_count,
        "pending_received": pending_received,
        "open_tickets": open_tickets,
    }


def get_achievement_badges(user, limit=6):
    if not user or not getattr(user, "id", None):
        return []

    offered = get_skill_value(user.id, "offered")
    wanted = get_skill_value(user.id, "wanted")
    has_profile = bool((user.location or "").strip() and offered and wanted)

    sent_requests = SwapRequest.query.filter_by(requester_id=user.id).count()
    accepted_requests = SwapRequest.query.filter(
        SwapRequest.status == "accepted",
        or_(SwapRequest.requester_id == user.id, SwapRequest.target_id == user.id),
    ).count()
    friends_count = get_current_user_connections().count()
    messages_sent = Message.query.filter_by(sender_id=user.id).count()
    tickets_count = SupportTicket.query.filter_by(user_id=user.id).count()

    badge_specs = [
        {
            "id": "profile_builder",
            "title": "Profile Builder",
            "description": "Complete location + offered/wanted skills.",
            "earned": has_profile,
        },
        {
            "id": "first_request",
            "title": "First Outreach",
            "description": "Send your first skill swap request.",
            "earned": sent_requests >= 1,
        },
        {
            "id": "collaborator",
            "title": "Collaborator",
            "description": "Get a swap request accepted.",
            "earned": accepted_requests >= 1,
        },
        {
            "id": "networker",
            "title": "Network Builder",
            "description": "Create 3 friend connections.",
            "earned": friends_count >= 3,
        },
        {
            "id": "conversation_starter",
            "title": "Conversation Starter",
            "description": "Send 5 chat messages.",
            "earned": messages_sent >= 5,
        },
        {
            "id": "feedback_loop",
            "title": "Feedback Loop",
            "description": "Use support/query at least once.",
            "earned": tickets_count >= 1,
        },
    ]

    earned_badges = [badge for badge in badge_specs if badge["earned"]]
    locked_badges = [badge for badge in badge_specs if not badge["earned"]]
    return (earned_badges + locked_badges)[: max(1, limit)]


def serialize_swap_request(item, skill_lookup, connection_lookup=None):
    requester_skills = skill_lookup.get(item.requester_id, {})
    target_skills = skill_lookup.get(item.target_id, {})
    connection_id = None
    if connection_lookup:
        pair = normalize_connection_pair(item.requester_id, item.target_id)
        connection_id = connection_lookup.get(pair)
    return {
        "id": item.id,
        "status": item.status,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "connection_id": connection_id,
        "requester": {
            "id": item.requester.id,
            "name": item.requester.name,
            "location": item.requester.location or "",
        },
        "target": {
            "id": item.target.id,
            "name": item.target.name,
            "location": item.target.location or "",
        },
        "requester_offered_skill": requester_skills.get("offered", ""),
        "requester_wanted_skill": requester_skills.get("wanted", ""),
        "target_offered_skill": target_skills.get("offered", ""),
        "target_wanted_skill": target_skills.get("wanted", ""),
    }


# ---------------- ROUTES ----------------


@app.route("/")
def home():
    recommended_matches = []
    trending_skills = get_trending_skills(limit=6)
    engagement_snapshot = None
    achievement_badges = []
    if current_user.is_authenticated:
        recommended_matches = get_personalized_recommendations(current_user, limit=6)
        engagement_snapshot = get_engagement_snapshot(current_user)
        achievement_badges = get_achievement_badges(current_user, limit=6)

    return render_template(
        "index.html",
        recommended_matches=recommended_matches,
        trending_skills=trending_skills,
        engagement_snapshot=engagement_snapshot,
        achievement_badges=achievement_badges,
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login_page"))


@app.route("/api/login", methods=["POST"])
def api_login():
    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    email = clean_text(data.get("email"), max_length=120)
    password = data.get("password") or ""

    if not email or not password:
        return json_error("Email and password are required.", 400)

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return json_error("Invalid credentials!", 401)

    login_user(user)
    return jsonify({"message": "Login successful!"})


@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        name = clean_text(request.form.get("name"), max_length=80)
        email = clean_text(request.form.get("email"), max_length=120)
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not name or not email or not password or not confirm:
            return render_template("register.html", error="All fields are required."), 400

        if not EMAIL_REGEX.match(email):
            return render_template("register.html", error="Enter a valid email address."), 400

        if len(password) < 6:
            return render_template("register.html", error="Password must be at least 6 characters."), 400

        if password != confirm:
            return render_template("register.html", error="Passwords do not match."), 400

        if User.query.filter_by(email=email).first():
            return render_template("register.html", error="Email already registered."), 409

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return render_template("register.html", error="Email already registered."), 409

        return redirect(url_for("login_page"))

    return render_template("register.html")


@app.route("/profile")
@login_required
def profile_page():
    return render_template("profile.html")


@app.route("/api/get_profile", methods=["GET"])
@login_required
def get_profile():
    offered_skill = get_skill_value(current_user.id, "offered")
    wanted_skill = get_skill_value(current_user.id, "wanted")
    return jsonify(
        {
            "name": current_user.name or "",
            "location": current_user.location or "",
            "availability": current_user.availability or "anytime",
            "visibility": "public" if current_user.is_public else "private",
            "skills_offered": offered_skill,
            "skills_wanted": wanted_skill,
            "has_profile": bool(offered_skill and wanted_skill),
        }
    )


@app.route("/api/update_profile", methods=["POST"])
@login_required
def update_profile():
    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    had_profile = has_configured_profile(current_user.id)

    name = clean_text(data.get("name"), max_length=80)
    location = clean_text(data.get("location"), max_length=100, allow_blank=True) or ""
    skills_offered = clean_text(data.get("skills_offered"), max_length=100)
    skills_wanted = clean_text(data.get("skills_wanted"), max_length=100)
    availability = clean_text(data.get("availability"), max_length=20)
    visibility = clean_text(data.get("visibility"), max_length=10)

    if not name:
        return json_error("Name is required.", 400)
    if not skills_offered or not skills_wanted:
        return json_error("Both offered and wanted skills are required.", 400)
    if availability and availability not in VALID_AVAILABILITY:
        return json_error("Invalid availability option.", 400)
    if visibility not in {"public", "private"}:
        return json_error("Visibility must be public or private.", 400)

    current_user.name = name
    current_user.location = location
    current_user.availability = availability or "anytime"
    current_user.is_public = visibility == "public"

    set_skill_value(current_user.id, "offered", skills_offered)
    set_skill_value(current_user.id, "wanted", skills_wanted)

    db.session.commit()
    action = "updated" if had_profile else "created"
    return jsonify({"message": f"Profile {action} successfully!", "action": action})


@app.route("/browse")
@login_required
def browse_page():
    return render_template("browse.html")


@app.route("/skills/offered", methods=["GET"])
@login_required
def list_offered_skills():
    query_text = clean_text(request.args.get("q"), max_length=100, allow_blank=True) or ""
    location_filter = clean_text(request.args.get("location"), max_length=100, allow_blank=True) or ""
    availability_filter = clean_text(request.args.get("availability"), max_length=20, allow_blank=True) or ""
    page = parse_positive_int(request.args.get("page"), 1, minimum=1)
    per_page = parse_positive_int(request.args.get("per_page"), 6, minimum=1, maximum=24)

    if availability_filter and availability_filter not in VALID_AVAILABILITY:
        return json_error("Invalid availability filter.", 400)

    q = (
        db.session.query(Skill, User)
        .join(User, Skill.user_id == User.id)
        .filter(Skill.type == "offered", User.is_public.is_(True), User.id != current_user.id)
    )

    if query_text:
        like = f"%{query_text}%"
        q = q.filter(or_(Skill.skill_name.ilike(like), User.name.ilike(like)))

    if location_filter:
        q = q.filter(User.location.ilike(f"%{location_filter}%"))

    if availability_filter:
        q = q.filter(User.availability == availability_filter)

    q = q.order_by(User.name.asc(), Skill.skill_name.asc())

    total = q.count()
    total_pages = (total + per_page - 1) // per_page if total else 0

    if total_pages and page > total_pages:
        page = total_pages

    offset = (page - 1) * per_page if total_pages else 0
    rows = q.offset(offset).limit(per_page).all()

    results = [
        {
            "user_id": user.id,
            "name": user.name,
            "location": user.location or "",
            "availability": user.availability or "",
            "skill": skill.skill_name,
        }
        for skill, user in rows
    ]

    return jsonify(
        {
            "items": results,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": total_pages,
                "has_prev": page > 1 and total_pages > 0,
                "has_next": page < total_pages,
            },
            "filters": {
                "q": query_text,
                "location": location_filter,
                "availability": availability_filter,
            },
        }
    )


@app.route("/swap_request", methods=["POST"])
@login_required
def create_swap_request():
    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    try:
        target_id = int(data.get("target_id"))
    except (TypeError, ValueError):
        return json_error("Valid target_id is required.", 400)

    if target_id == current_user.id:
        return json_error("You cannot request a swap with yourself.", 400)

    target_user = db.session.get(User, target_id)
    if not target_user or not target_user.is_public:
        return json_error("Target user not found or not available.", 404)

    existing_pending = SwapRequest.query.filter_by(
        requester_id=current_user.id,
        target_id=target_id,
        status="pending",
    ).first()
    if existing_pending:
        return json_error("A pending swap request already exists for this user.", 409)

    new_request = SwapRequest(requester_id=current_user.id, target_id=target_id, status="pending")
    db.session.add(new_request)
    db.session.commit()
    return jsonify({"message": "Swap request sent successfully!", "request_id": new_request.id}), 201


@app.route("/respond_swap/<int:request_id>", methods=["POST"])
@login_required
def respond_swap(request_id):
    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    requested_status = clean_text(data.get("status"), max_length=20)
    if requested_status not in {"accepted", "rejected", "cancelled"}:
        return json_error("Invalid status.", 400)

    swap_request = db.session.get(SwapRequest, request_id)
    if not swap_request:
        return json_error("Swap request not found.", 404)

    if swap_request.status != "pending":
        return json_error(f"Request already {swap_request.status}.", 409)

    if requested_status == "cancelled":
        if swap_request.requester_id != current_user.id:
            return json_error("Only the requester can cancel this request.", 403)
    else:
        if swap_request.target_id != current_user.id:
            return json_error("Only the target user can respond to this request.", 403)

    swap_request.status = requested_status
    if requested_status == "accepted":
        create_connection_if_missing(
            swap_request.requester_id,
            swap_request.target_id,
            source_swap_request_id=swap_request.id,
        )
    db.session.commit()
    return jsonify({"message": f"Swap request {requested_status} successfully!"})


@app.route("/api/swap_requests", methods=["GET"])
@login_required
def get_swap_requests():
    sent = (
        SwapRequest.query.filter_by(requester_id=current_user.id)
        .order_by(SwapRequest.created_at.desc())
        .all()
    )
    received = (
        SwapRequest.query.filter_by(target_id=current_user.id)
        .order_by(SwapRequest.created_at.desc())
        .all()
    )

    all_user_ids = {current_user.id}
    for item in sent + received:
        all_user_ids.add(item.requester_id)
        all_user_ids.add(item.target_id)
    skill_lookup = user_skill_map(all_user_ids)
    connection_lookup = {}
    if sent or received:
        involved_pairs = {normalize_connection_pair(item.requester_id, item.target_id) for item in sent + received}
        user_ids_flat = {uid for pair in involved_pairs for uid in pair}
        connection_rows = Connection.query.filter(
            Connection.is_active.is_(True),
            Connection.user1_id.in_(user_ids_flat),
            Connection.user2_id.in_(user_ids_flat),
        ).all()
        for connection in connection_rows:
            connection_lookup[(connection.user1_id, connection.user2_id)] = connection.id

    return jsonify(
        {
            "sent": [serialize_swap_request(item, skill_lookup, connection_lookup) for item in sent],
            "received": [serialize_swap_request(item, skill_lookup, connection_lookup) for item in received],
        }
    )


@app.route("/friends")
@login_required
def friends_page():
    return render_template("friends.html")


@app.route("/api/friends", methods=["GET"])
@login_required
def get_friends():
    connections = get_current_user_connections().all()
    user_ids = {current_user.id}
    for connection in connections:
        user_ids.update([connection.user1_id, connection.user2_id])
    skill_lookup = user_skill_map(user_ids)

    items = []
    for connection in connections:
        serialized = serialize_connection(connection, viewer_id=current_user.id, skill_lookup=skill_lookup)
        if serialized:
            items.append(serialized)
    return jsonify({"items": items})


@app.route("/chat/<int:connection_id>")
@login_required
def chat_page(connection_id):
    connection = db.session.get(Connection, connection_id)
    if not connection or not connection.is_active:
        return redirect(url_for("friends_page"))
    if not user_is_connection_participant(connection, current_user.id):
        return redirect(url_for("friends_page"))

    friend = get_other_connection_user(connection, current_user.id)
    return render_template("chat.html", connection=connection, friend=friend)


@app.route("/api/chat/<int:connection_id>/messages", methods=["GET", "POST"])
@login_required
def chat_messages(connection_id):
    connection = db.session.get(Connection, connection_id)
    if not connection or not connection.is_active:
        return json_error("Chat not found.", 404)
    if not user_is_connection_participant(connection, current_user.id):
        return json_error("You are not allowed to access this chat.", 403)

    if request.method == "GET":
        limit = parse_positive_int(request.args.get("limit"), 100, minimum=1, maximum=300)
        after_id = parse_positive_int(request.args.get("after_id"), 0, minimum=0)
        q = Message.query.filter_by(connection_id=connection.id).order_by(Message.id.asc())
        if after_id > 0:
            q = q.filter(Message.id > after_id)
        messages = q.limit(limit).all()
        return jsonify({"items": [serialize_message(msg) for msg in messages]})

    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    content = clean_text(data.get("content"), max_length=1000)
    if not content:
        return json_error("Message content is required.", 400)

    message = Message(connection_id=connection.id, sender_id=current_user.id, content=content)
    db.session.add(message)
    db.session.commit()
    return jsonify({"message": "Message sent successfully!", "item": serialize_message(message)}), 201


@app.route("/support")
@login_required
def support_page():
    return render_template("support.html")


@app.route("/admin/support")
@login_required
def admin_support_page():
    blocked = require_admin_access()
    if blocked:
        return blocked
    return render_template("admin-support.html")


@app.route("/api/support_tickets", methods=["GET", "POST"])
@login_required
def support_tickets():
    if request.method == "GET":
        tickets = (
            SupportTicket.query.filter_by(user_id=current_user.id)
            .order_by(SupportTicket.created_at.desc())
            .all()
        )
        return jsonify({"items": [serialize_support_ticket(ticket) for ticket in tickets]})

    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    category = clean_text(data.get("category"), max_length=30) or "other"
    subject = clean_text(data.get("subject"), max_length=120)
    related_skill = clean_text(data.get("related_skill"), max_length=100, allow_blank=True) or ""
    related_location = clean_text(data.get("related_location"), max_length=100, allow_blank=True) or ""
    description = clean_text(data.get("description"), max_length=2000)

    if category not in VALID_SUPPORT_CATEGORIES:
        return json_error("Invalid support category.", 400)
    if not subject:
        return json_error("Subject is required.", 400)
    if not description:
        return json_error("Description is required.", 400)

    ticket = SupportTicket(
        user_id=current_user.id,
        category=category,
        subject=subject,
        related_skill=related_skill,
        related_location=related_location,
        description=description,
        status="open",
    )
    db.session.add(ticket)
    db.session.commit()
    return jsonify({"message": "Query submitted successfully!", "item": serialize_support_ticket(ticket)}), 201


@app.route("/api/admin/support_tickets", methods=["GET"])
@login_required
def admin_support_tickets():
    blocked = require_admin_access()
    if blocked:
        return blocked

    status = clean_text(request.args.get("status"), max_length=20, allow_blank=True)
    query_text = clean_text(request.args.get("query"), max_length=100, allow_blank=True)
    limit = parse_positive_int(request.args.get("limit"), 100, minimum=1, maximum=500)

    tickets_query = SupportTicket.query.join(User).order_by(
        SupportTicket.updated_at.desc(), SupportTicket.created_at.desc()
    )
    if status and status != "all":
        if status not in VALID_SUPPORT_STATUSES:
            return json_error("Invalid support status filter.", 400)
        tickets_query = tickets_query.filter(SupportTicket.status == status)

    if query_text:
        term = f"%{query_text}%"
        tickets_query = tickets_query.filter(
            or_(
                SupportTicket.subject.ilike(term),
                SupportTicket.description.ilike(term),
                SupportTicket.related_skill.ilike(term),
                SupportTicket.related_location.ilike(term),
                User.name.ilike(term),
                User.email.ilike(term),
            )
        )

    tickets = tickets_query.limit(limit).all()

    status_counts_rows = (
        db.session.query(SupportTicket.status, func.count(SupportTicket.id))
        .group_by(SupportTicket.status)
        .all()
    )
    counts = {status_key: 0 for status_key in sorted(VALID_SUPPORT_STATUSES)}
    total_count = 0
    for status_key, count in status_counts_rows:
        counts[status_key] = int(count)
        total_count += int(count)

    return jsonify(
        {
            "items": [serialize_support_ticket(ticket) for ticket in tickets],
            "summary": {"total": total_count, "by_status": counts},
        }
    )


@app.route("/api/admin/support_tickets/<int:ticket_id>", methods=["PATCH"])
@login_required
def admin_update_support_ticket(ticket_id):
    blocked = require_admin_access()
    if blocked:
        return blocked

    ticket = db.session.get(SupportTicket, ticket_id)
    if not ticket:
        return json_error("Support ticket not found.", 404)

    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    next_status = clean_text(data.get("status"), max_length=20)
    if next_status not in VALID_SUPPORT_STATUSES:
        return json_error("Invalid support status.", 400)

    ticket.status = next_status
    db.session.commit()
    return jsonify(
        {
            "message": f"Ticket #{ticket.id} marked as {next_status.replace('_', ' ')}.",
            "item": serialize_support_ticket(ticket),
        }
    )


@app.route("/api/support_tickets/<int:ticket_id>", methods=["PATCH"])
@login_required
def update_support_ticket(ticket_id):
    ticket = db.session.get(SupportTicket, ticket_id)
    if not ticket or ticket.user_id != current_user.id:
        return json_error("Support ticket not found.", 404)

    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

    next_status = clean_text(data.get("status"), max_length=20)
    if next_status not in VALID_SUPPORT_STATUSES:
        return json_error("Invalid support status.", 400)

    # Keep user actions simple: they can reopen or mark their own ticket resolved/closed.
    allowed_user_statuses = {"open", "resolved", "closed"}
    if next_status not in allowed_user_statuses:
        return json_error("This status can only be set by support staff.", 403)

    ticket.status = next_status
    db.session.commit()
    return jsonify(
        {
            "message": f"Query marked as {next_status.replace('_', ' ')}.",
            "item": serialize_support_ticket(ticket),
        }
    )


@app.route("/api/suggestions/locations", methods=["GET"])
def suggest_locations():
    limit = parse_positive_int(request.args.get("limit"), 8, minimum=1, maximum=20)
    q = request.args.get("q")
    return jsonify({"items": location_suggestions(q, limit=limit)})


@app.route("/api/suggestions/skills", methods=["GET"])
def suggest_skills():
    limit = parse_positive_int(request.args.get("limit"), 8, minimum=1, maximum=20)
    q = request.args.get("q")
    return jsonify({"items": skill_suggestions(q, limit=limit)})


@app.route("/swap-requests")
@login_required
def swap_requests_page():
    return render_template("swap-requests.html")


def ensure_db_tables():
    """Create tables on startup so gunicorn/Railway works like local runs."""
    with app.app_context():
        db.create_all()


# Ensure tables exist even when app is started via gunicorn (Railway), not __main__.
ensure_db_tables()


if __name__ == "__main__":
    app.run(
        host=app.config["APP_HOST"],
        port=int(os.getenv("PORT", app.config["APP_PORT"])),
        debug=bool(app.config["DEBUG"]),
    )
