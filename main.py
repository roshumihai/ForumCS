from flask import Flask, render_template, url_for, redirect, request, jsonify, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import pytz
import uuid
import os
import logging
import re

basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads')

db = SQLAlchemy()
app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+ os.path.join(basedir, "database.db")
app.config["SECRET_KEY"] = "Abecedar1234"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TIMEZONE'] = 'Europe/Bucharest'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Strict'


db.init_app(app)
migrate = Migrate(app, db)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+ os.path.join(basedir, "database.db")
app.config["SECRET_KEY"] = "Abecedar1234"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Database Models Admin, User, Register, Login
class Admin(db.Model):
    admin_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('admin', uselist=False))

    def __init__(self, user=None, *args, **kwargs):
        super(Admin, self).__init__(*args, **kwargs)
        if user:
            self.user = user
            self.username = user.username

    def __repr__(self):
        return f"<Admin id:{self.admin_id}, user_id: {self.user_id}, user_username:{self.username}>"

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime(), default=datetime.now())

    def __init__(self, username, password):
        self.username = username.lower()
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def __repr__(self):
        return f"<User id:{self.user_id}, username: {self.username}, member since: {self.created_at}"

    def is_active(self):
        return True

    def get_id(self):
        return str(self.user_id)

    def is_authenticated(self):
        return True


class Topic(db.Model):
    topic_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    post = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('topics', lazy='joined'))
    image_ref = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("Username already exists. Please choose a different username.")

        return True

    def validate_password(self, password):
        if not re.search(r'[A-Z]', password.data):
            raise ValidationError("Pasword must contain at least one uppercase letter.")

        if not re.search(r'\d', password.data):
            raise ValidationError("Password must contain at least one digit.")

        if len(password.data) < 8:
            raise ValidationError("Password must be at least 8 characters long.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class AddAdmin(FlaskForm):
    admin_user = TextAreaField(render_kw={"placeholder": "Enter username"})
    submit = SubmitField("Add")


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect('dashboard')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    add_admin_form = AddAdmin()
    if add_admin_form.validate_on_submit():
        username = add_admin_form.admin_user.data
        users = User.query.all()

        if username in [user.username for user in users]:
            user = User.query.filter_by(username=username).first()
            if user:
                new_admin = Admin(user=user)

                db.session.add(new_admin)
                db.session.commit()
                return jsonify({'username': user.username})

    if current_user.admin or current_user.username.lower() == "roshu" or current_user.username.lower() == "darkdevil":
        return render_template('admin.html', add_admin_form=add_admin_form)
    else:
        return "Unauthorized", 401

@app.route('/home')
def home():
    return render_template('acasa.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        logger = logging.getLogger('login_route')
        logger.info("Form validation")

        username = form.username.data.lower()
        user = User.query.filter_by(username=username).first()

        if user:
            logger.info("User found.")

            if bcrypt.check_password_hash(user.password, form.password.data):
                logger.info("Password matched. Logging in...")
                login_user(user)

                return redirect(url_for('home'))
            else:
                logger.warning("Password incorrect.")
                form.password.errors.append("Incorrect password. Please try again.")
        else:
            logger.warning("User not found")
            form.username.errors.append("User does not exist.")

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    logger = logging.getLogger('register_route')
    form = RegisterForm()

    if form.validate_on_submit():
        form.validate_password(form.password)

        new_user = User(username=form.username.data, password=form.password.data)

        logger.info(f"u.{new_user.username}, p.{form.password.data}")

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/regulament')
def regulament():
    return render_template('regulament.html')


@app.route('/discutiiGenerale', methods=['POST', 'GET'])
def discutiiGenerale():
    topics = Topic.query.all()

    return render_template('discutiiGenerale.html', topics=topics)

@app.route('/new-topic', methods=['POST', 'GET'])
@login_required
def new_topic():
    if not current_user.is_authenticated:
        return redirect('login')

    if request.method == 'POST':
        topic = Topic()

        topic_title = request.form['title']
        topic_post = request.form['post']
        topic_photo = request.files['photo']

        if topic_title:
            topic.title = topic_title
        if topic_post:
            topic.post = topic_post
        if topic_photo:
            filename = secure_filename(topic_photo.filename)

            # Create a unique filename with UUID and save the uploaded file
            filename = str(uuid.uuid4()) + '_' + filename
            topic_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            topic.image_ref = topic_photo

        topic.user_id = current_user.user_id

        db.session.add(topic)
        db.session.commit()

        return redirect(url_for('discutiiGenerale'))

    return render_template('new-topic.html')

@app.route('/tutorial')
def tutorial():
    return render_template('tutorial.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)