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

app.config['JWT_SECRET_KEY'] = os.environ.get('CICAPP_BACKEND_JWT_SECRET',os.getrandom(16))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=4)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

app.config['SECRET_KEY'] = os.environ.get('CICAPP_BACKEND_SECRET', '123456')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///.local/lite.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)

db = SQLAlchemy(app)
from models import User

# TODO: use database
blacklist_jwt = set()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist_jwt

### Endpoints

@app.route('/helloworld')
def hello_world():
    return "HelloWorld"

# Parameters: username, password, email
# Parameters will be given through POST body form
@app.route('/register', methods=['POST'])
def register():
    usern = request.form['username']
    passw = request.form['password']
    pwhash = bcrypt.hashpw(passw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    email_ = request.form['email']
    if User.query.filter_by(username=usern).first() != None:
        return jsonify(msg='User already registered'), 403
    new_user = User(username=usern, password=pwhash, email=email_)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(msg='Success'), 200


# Parameters: username, password
# Parameters will be given through POST body form
@app.route('/login', methods=['POST'])
def login():
    usern = request.form['username']
    passw = request.form['password']
    user = User.query.filter_by(username=usern).first()
    if user == None:
        return jsonify(msg='User not registered'), 401
    if not bcrypt.checkpw(passw.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify(msg='Bad creditentials'), 401
    token = create_access_token(identity=usern)
    return jsonify(msg='Success', token=token), 200


@app.route('/.dev/jwtecho')
@jwt_required
def jwtecho():
    return jsonify(msg='Success'), 200

# Requires authentication
# TODO: JWT token handling
@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist_jwt.add(jti)
    return jsonify(msg='Success'), 200

@app.route('/delete_user', methods=['POST'])
@jwt_required
def delete_user():
    usern = get_jwt_identity()
    User.query.filter_by(username=usern).delete()
    db.session.commit()
    logout()
    return jsonify(msg='Success'), 200

### Main

if __name__ == '__main__':
    app.run()

