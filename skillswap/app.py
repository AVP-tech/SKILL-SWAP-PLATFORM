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
from sqlalchemy import or_
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


app = Flask(__name__)

APP_ENV = os.getenv("APP_ENV", os.getenv("FLASK_ENV", "development")).strip().lower()
IS_PRODUCTION = APP_ENV == "production"

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///skill_swap.db")
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
    return {"csrf_token": generate_csrf}


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


def serialize_swap_request(item, skill_lookup):
    requester_skills = skill_lookup.get(item.requester_id, {})
    target_skills = skill_lookup.get(item.target_id, {})
    return {
        "id": item.id,
        "status": item.status,
        "created_at": item.created_at.isoformat() if item.created_at else None,
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
    return render_template("index.html")


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
    return jsonify(
        {
            "name": current_user.name or "",
            "location": current_user.location or "",
            "availability": current_user.availability or "anytime",
            "visibility": "public" if current_user.is_public else "private",
            "skills_offered": get_skill_value(current_user.id, "offered"),
            "skills_wanted": get_skill_value(current_user.id, "wanted"),
        }
    )


@app.route("/api/update_profile", methods=["POST"])
@login_required
def update_profile():
    data = get_json_body()
    if data is None:
        return json_error("Invalid JSON payload.", 400)

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
    return jsonify({"message": "Profile updated successfully!"})


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

    return jsonify(
        {
            "sent": [serialize_swap_request(item, skill_lookup) for item in sent],
            "received": [serialize_swap_request(item, skill_lookup) for item in received],
        }
    )


@app.route("/swap-requests")
@login_required
def swap_requests_page():
    return render_template("swap-requests.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(
        host=app.config["APP_HOST"],
        port=app.config["APP_PORT"],
        debug=bool(app.config["DEBUG"]),
    )
