from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, EmailField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Regexp

class QuestionForm(FlaskForm):
    subject = StringField('제목', validators=[DataRequired('제목은 필수입력 항목입니다.')])
    content = TextAreaField('내용', validators=[DataRequired('내용은 필수입력 항목입니다.')])

class AnswerForm(FlaskForm):
    content = TextAreaField('내용', validators=[DataRequired('내용은 필수입력 항목입니다.')])

class UserCreateForm(FlaskForm):
    username = StringField('사용자 이름', validators=[
        DataRequired('아이디를 입력하세요.'), Length(min=3, max=25), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
        '아이디는 문자, 숫자, 점, 밑줄만 사용할 수 있습니다.')])
    password1 = PasswordField('비밀번호', validators=[
        DataRequired('비밀번호를 입력하세요.'), EqualTo('password2', message='비밀번호가 일치하지 않습니다.')])
    password2 = PasswordField('비밀번호 확인', validators=[DataRequired('비밀번호를 한번 더 입력하세요.')])
    email = EmailField('이메일', validators=[DataRequired('이메일을 입력하세요.'), Length(1,64), Email('이메일 주소가 아닙니다.')])
    location = StringField('사는 곳', validators=[Length(0, 64)])
    about_me = TextAreaField('나는 ')
    submit = SubmitField('회원등록')

class UserLoginForm(FlaskForm):
    username = StringField('사용자이름', validators=[DataRequired(), Length(min=3, max=25)])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    remember_me = BooleanField('로그인 상태 유지')
    submit = SubmitField('로그인')

class CommentForm(FlaskForm):
    content = TextAreaField('내용', validators=[DataRequired()])

