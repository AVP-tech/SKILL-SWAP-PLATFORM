from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skill_swap.db'
app.config['SECRET_KEY'] = 'secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# ---------------- MODELS ----------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    location = db.Column(db.String(100), nullable=True)
    availability = db.Column(db.String(100), nullable=True)
    is_public = db.Column(db.Boolean, default=True)

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    skill_name = db.Column(db.String(50))
    type = db.Column(db.String(10))  # 'offered' or 'wanted'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({'message': 'Login successful!'})
    else:
        return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        data = request.form
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(name=data['name'], email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login_page'))
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html')

@app.route('/api/get_profile', methods=['GET'])
@login_required
def get_profile():
    offered_skill = Skill.query.filter_by(user_id=current_user.id, type='offered').first()
    wanted_skill = Skill.query.filter_by(user_id=current_user.id, type='wanted').first()

    return jsonify({
        'name': current_user.name,
        'location': current_user.location,
        'availability': current_user.availability,
        'visibility': 'public' if current_user.is_public else 'private',
        'skills_offered': offered_skill.skill_name if offered_skill else '',
        'skills_wanted': wanted_skill.skill_name if wanted_skill else ''
    })

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json

    current_user.name = data.get('name')
    current_user.location = data.get('location')
    current_user.availability = data.get('availability')
    current_user.is_public = True if data.get('visibility') == 'public' else False

    Skill.query.filter_by(user_id=current_user.id).delete()

    offered = Skill(user_id=current_user.id, skill_name=data['skills_offered'], type='offered')
    wanted = Skill(user_id=current_user.id, skill_name=data['skills_wanted'], type='wanted')
    db.session.add(offered)
    db.session.add(wanted)

    db.session.commit()

    return jsonify({'message': 'Profile updated successfully!'})

@app.route('/browse')
@login_required
def browse_page():
    return render_template('browse.html')

@app.route('/swap-requests')
@login_required
def swap_requests_page():
    return render_template('swap-requests.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)