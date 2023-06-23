from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash
from flask_login import UserMixin, LoginManager
from flask_marshmallow import Marshmallow
import uuid, secrets

db = SQLAlchemy()
login_manager = LoginManager()
ma = Marshmallow()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    id = db.Column(db.String, primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    token = db.Column(db.String, default='', unique=True)
    join_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    phone_number = db.Column(db.Integer, nullable=True)

    def __init__(self, username, email, phone_number, password):
        self.id =  self.set_id()
        self.username = username
        self.email = email
        self.phone_number = phone_number
        self.password = self.set_password(password)
        self.token = self.set_token(32)

    def set_id(self):
        return str(uuid.uuid4())

    def set_password(self, password):
        return generate_password_hash(password)

    def set_token(self, length):
        return secrets.token_hex(length)

    def __repr__(self):
        return f'username: {self.username}, email: {self.email} was added to Users'

class Address(db.Model):
    id = db.Column(db.String, primary_key=True)
    street = db.Column(db.String)
    city = db.Column(db.String)
    state = db.Column(db.String)
    zipcode = db.Column(db.Integer)
    user_token = db.Column(db.String, db.ForeignKey('user.token'))

    def __init__(self, street, city, state, zipcode, user_token):
        self.id = self.set_id()
        self.street = street
        self.city = city
        self.state = state
        self.zipcode = zipcode
        self.user_token = user_token

    def set_id(self):
        return str(uuid.uuid4())

    def __repr__(self):
        return f'The address {self.street}, {self.city}, {self.state} {self.zipcode} was added'

class AddressSchema(ma.Schema):
    class Meta:
        fields = ['id', 'street', 'city', 'state', 'zipcode']
address_schema = AddressSchema()
addresses_schema = AddressSchema(many=True)