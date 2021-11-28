from flask import Blueprint, url_for, render_template, flash, request, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, TextAreaField, PasswordField, EmailField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Regexp
from werkzeug.utils import redirect
from flask_login import current_user
from flask.globals import current_app

import functools

from pybo import db
from pybo.forms import UserCreateForm, UserLoginForm
from pybo.models import User
from sqlalchemy import exc

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/signup/', methods=('GET', 'POST'))
def signup():
    form = UserCreateForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            user = User(username=form.username.data,
                        password=generate_password_hash(form.password1.data),
                        email=form.email.data)
            try:
                db.session.add(user)
                db.session.commit()
                flash('가입되었습니다. 로그인 하세요.')
                return redirect(url_for('main.index'))
            except exc.IntegrityError:
                db.session.rollback()
                flash('사용중인 이메일 주소입니다.')
        else:
            flash('이미 등록된 사용자입니다.')
    return render_template('auth/signup.html', form=form)

@bp.route('/login/', methods=('GET', 'POST'))
def login():
    form = UserLoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        error = None
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            error = "존재하지 않는 사용자입니다."
        elif not check_password_hash(user.password, form.password.data):
            error = "비밀번호가 올바르지 않습니다."
        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('main.index'))
        flash(error)
    return render_template('auth/login.html', form=form)

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get(user_id)

@bp.route('/logout/')
def logout():
    session.clear()
    return redirect(url_for('main.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

@bp.route('/profile/', methods=('GET', 'POST'))
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('auth/profile.html', user=user, posts=posts)


