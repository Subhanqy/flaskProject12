from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo, Length
import re

# Validation of the password having correct data
def validate_data( self, password):
    p = re.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,12}$")
    if not p.match(password.data):
        raise ValidationError("Must contain one lowercase and uppercase letter, one number and one special character. Password should also be 6-12 characters long")

# Invalid characters cannot be used
def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed.")

# Validation for phone number
def validnumber(self, phone):
    pattern = re.compile("^[\dA-Z]{4}-[\dA-Z]{3}-[\dA-Z]{4}$", re.IGNORECASE)
    if not pattern.match(phone.data):
        raise ValidationError("Must be xxxx-xxx-xxxx")

# Defining register form and its variables with different criteria of validation
class RegisterForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    phone = StringField(validators=[DataRequired(), validnumber])
    password = PasswordField(validators=[ DataRequired(), validate_data])
    confirm_password = PasswordField(validators=[EqualTo('password', message='Both password fields must be equal!'), DataRequired()])
    submit = SubmitField()

# Defining login form and its variables with different criteria of validation
class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired(), Length(min=6, max=6)])
    recaptcha = RecaptchaField()

    submit = SubmitField()

