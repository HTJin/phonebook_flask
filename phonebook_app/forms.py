from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TelField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional

class LoginForm(FlaskForm):
    email = StringField('email:', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField()

class RegisterForm(FlaskForm):
    username = StringField('username:', validators=[DataRequired(), Length(min=3, max=40)])
    email = StringField('email:', validators=[DataRequired(), Email()])
    phone_number = TelField('phone number:', validators=[DataRequired()])
    password = PasswordField('new password:', validators=[DataRequired(), EqualTo('confirm', message='passwords are not matching')])
    confirm = PasswordField('confirm password:', validators=[DataRequired(), EqualTo('password', message='passwords are not matching')])
    submit = SubmitField()

class AddressForm(FlaskForm):
    street = StringField('street:', validators=[DataRequired()])
    city = StringField('city:', validators=[DataRequired()])
    state = StringField('state:', validators=[DataRequired()])
    zipcode = IntegerField('zip code:', validators=[Optional()])
    submit = SubmitField()