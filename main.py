import datetime
import os
from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_raw_jwt
)
from flask_sqlalchemy import SQLAlchemy
import bcrypt

### Inits, setups
app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.environ.get('INTA_BACKEND_JWT_SECRET',os.getrandom(16))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=4)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

app.config['SECRET_KEY'] = os.environ.get('INTA_BACKEND_SECRET', '123456')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///.local/lite.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['APPLICATION_ROOT'] = '/api'

jwt = JWTManager(app)

db = SQLAlchemy(app)
from models import User

# TODO: use database
blacklist_jwt = set()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist_jwt

@jwt.expired_token_loader
@jwt.invalid_token_loader
@jwt.unauthorized_loader
def token_error():
    return jsonify(error='User is not authorized for this call'), 401

###### Endpoints

@app.route('/helloworld')
def hello_world():
    return "HelloWorld"




### Password

@app.route('/user/register', methods=['POST'])
def register():
    data = request.get_json()
    user = data.get('user', None)
    password = data.get('password', None)
    pwhash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    email = data.get('email', None)
    if User.query.filter_by(username=user).first() != None:
        return jsonify(error='Username is already in use'), 409
    new_user = User(username=user, password=pwhash, email=email)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(msg='Success'), 200

@app.route('/user/login', methods=['GET'])
def login():
    data = request.get_json()
    user = data.get('user', None)
    password = data.get('password', None)
    userdb = User.query.filter_by(username=user).first()
    if userdb == None:
        return jsonify(error='Wrong username or password'), 401
    if not bcrypt.checkpw(password.encode('utf-8'), userdb.password.encode('utf-8')):
        return jsonify(error='Wrong username or password'), 401
    token = create_access_token(identity=user)
    return jsonify(msg='Success', token=token), 200

@app.route('/user/passwordreset', methods=['POST'])
def passwordreset():
    data = request.get_json()
    username = data.get('user', None)
    email = data.get('email', None)
    user = None
    if username:
        user = User.query.filter_by(username=username).first()
    if email:
        user = User.query.filter_by(email=email).first()
    if user == None:
        return jsonify(error='User not found'), 404
    # send email to user.email
    return jsonify(msg='Success'), 200

@app.route('/.dev/jwtecho')
@jwt_required
def jwtecho():
    return jsonify(msg='Success'), 200

# Requires authentication
@app.route('/user/logout', methods=['POST'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist_jwt.add(jti)
    return jsonify(msg='Success'), 200




### User data

@app.route('/user/profile', methods=['POST'])
@jwt_required
def profile_write():
    pass


@app.route('/user/profile', methods=['GET'])
@jwt_required
def profile_read():
    pass

@app.route('/university', methods=['POST'])
@jwt_required
def university_add():
    pass

@app.route('/university/all')
@jwt_required
def university_all():
    pass

@app.route('/university/students')
@jwt_required
def university_students():
    pass


### Main

from werkzeug.middleware.dispatcher import DispatcherMiddleware

app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/api": app})

if __name__ == '__main__':
   app.run('0.0.0.0', 5080)


