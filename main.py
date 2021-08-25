import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# flask_login manager for authentication
login_manager = LoginManager()
login_manager.init_app(app)


# creates table in database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


if not os.path.exists('users.db'):
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")

    elif request.method == 'POST':

        email = request.form.get('email')

        if User.query.filter_by(email=email).first():
            flash('A user already exists with that email. We redirected you to login.')
            return redirect(url_for('login'))

        pw_hashed_salted = generate_password_hash(password=request.form.get('password'), method='pbkdf2:sha256',
                                                  salt_length=8)

        new_user = User(
            id=request.form.get('id'),
            email=request.form.get('email'),
            password=pw_hashed_salted,
            name=request.form.get('name')
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for('secrets'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        pw = request.form.get('password')


        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email does not exist. Please try again or register.')
            return redirect(url_for('login'))

        if not check_password_hash(pwhash=user.password, password=pw):
            flash('Invalid credentials. Please reenter your email and password.')
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('secrets'))


    return render_template("login.html")


@app.route('/secrets', methods=['GET', 'POST'])
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download')
@login_required
def download():
    return send_from_directory('static',
                               'files/cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
