# IMPORTS
import logging
from datetime import datetime
from functools import wraps

import bcrypt
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request

from markupsafe import Markup

from app import db
from models import User
from users.forms import RegisterForm, LoginForm
from flask_login import login_user, logout_user, current_user, login_required

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# For login management, confirming different user access.
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                return render_template('403.html')
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Notifies admin when someone has registered
        logging.warning('SECURITY - User registration [%s , %s]',
                        form.email.data, request.remote_addr)

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # Setting attempts to 0
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0
    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # Dependent on the input will decide the route of the user
        if not user \
                or not bcrypt.checkpw(form.password.data.encode('utf-8'), user.password) \
                or not pyotp.TOTP(user.pinkey).verify(form.pin.data):
            session['authentication_attempts'] += 1
            # if user has too many attempts then the admin is notified
            logging.warning('SECURITY - Reset [%s,%s]',
                            form.email.data,
                            request.remote_addr)
            # if more than 3 attempts used,  the user will need to reactivate attempts
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Number of incorrect login attempts exceeded.Please click <a href="/reset">here</a> to '
                             'reset.'))
                return render_template('users/login.html')
            # everytime there is an incorrect login the attempts will be reduced
            flash('Please check your login details and try again,{} login attempts remaining'.format(
                3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)
        login_user(user)
        # shows security of logged-in user
        logging.warning('SECURITY - Log in [%s, %s,, %s]',
                        current_user.id,
                        current_user.email,
                        request.remote_addr)

        # Implements new login times to database
        user.last_login = user.current_login
        user.current_login = datetime.now()
        db.session.add(user)
        db.session.commit()

        # Dependent on roles, will choose where the user goes next
        if current_user.role == 'admin':
            return redirect(url_for('admin.admin'))
        else:
            return redirect(url_for('users.profile'))

    else:
        return render_template('users/login.html', form=form)

# reset attempts
@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))

# Logs the user out
@users_blueprint.route('/logout')
@login_required
def logout():
    logging.warning('SECURITY - Log out [%s, %s]',
                    current_user.id,
                    current_user.email)
    logout_user()
    return redirect(url_for('index'))


# view user profile
@users_blueprint.route('/profile')
@login_required
@requires_roles('user')
def profile():
    return render_template('users/profile.html', firstname=current_user.firstname)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)

# View admin, Notifies when admin has tried to be accessed
@users_blueprint.route('/admin')
@login_required
@requires_roles('admin')
def admin():
    logging.warning('SECURITY - User attempts Lottery [%s, %s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    current_user.role,
                    request.remote_addr)
    return render_template('admin/admin.html')

# View admin, Notifies when lottery has tried to be accessed
@users_blueprint.route('/lottery')
@login_required
@requires_roles('user')
def lottery():
    logging.warning('SECURITY - Lottery [%s, %s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    current_user.role,
                    request.remote_addr)
    return render_template('lottery/lottery.html')
