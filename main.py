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
from models import *

# TODO: use database
blacklist_jwt = set()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist_jwt

@jwt.expired_token_loader
@jwt.invalid_token_loader
@jwt.unauthorized_loader
def token_error(err):
    return jsonify(error='User is not authorized for this call', err=err), 401

###### Endpoints

@app.route('/helloworld')
def hello_world():
    return "HelloWorld"




### Login/Password

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
    username = data.get('user', None)
    password = data.get('password', None)
    user = User.query.filter_by(username=username).first()
    if user == None:
        return jsonify(error='Wrong username or password'), 401
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify(error='Wrong username or password'), 401
    token = create_access_token(identity=user.id)
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
    data = request.get_json()
    username = data['user']
    user = User.query.filter_by(username = username).first()
    if 'user' in data:
        user.username = data['user']
    if 'password' in data:
        password = data['password']
        pwhash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password = pwhash
    if 'name' in data:
        user.name = data['name']
    if 'email' in data:
        user.email = data['email']
    if 'university_id' in data:
        user.university_id = data['university_id']
    if 'group' in data:
        user.group = data['group']
    if 'activity' in data:
        user.activity = data['activity']
    db.session.add(user)
    db.session.commit()
    if 'contact' in data:
        UserContact.query.filter_by(user_id = user.id).delete()
        for cform in data['contact']:
            new_cont = UserContact(user_id = user.id, form = cform, address = data['contact'][cform])
            db.session.add(new_cont)
        db.session.commit()
    return jsonify(msg='Success'), 200

@app.route('/user/profile', methods=['GET'])
@jwt_required
def profile_read():
    username = request.get_json()['user']
    user = User.query.filter_by(username=username).first()
    return jsonify({
            'user_id': user.id,
            'user': user.username,
            'name': user.name,
            'email': user.email,
            'university_id': user.university_id,
            'group': user.group,
            'activity': user.activity,
            'contact': {uc.form: uc.address for uc in UserContact.query.filter_by(user_id = user.id).all()} 
        }), 200





### University

@app.route('/university', methods=['POST'])
@jwt_required
def university_add():
    data = request.get_json()
    university = data['university']
    uni = University.query.filter_by(university=university).first()
    if uni == None:
        uni = University(university=university)
        db.session.add(uni)
        db.session.commit()
    return jsonify({uni.id : uni.university}), 200

@app.route('/university/all')
@jwt_required
def university_all():
    all_uni = University.query.all()
    ret = {}
    for uni in all_uni:
        ret[uni.id] = uni.university
    return jsonify(ret), 200

@app.route('/university/students')
@jwt_required
def university_students():
    uni_id = request.get_json()['university_id']
    students = User.query.filter_by(university_id=uni_id).all()
    ret = []
    for st in students:
        ret.append(st.username)
    return jsonify(ret), 200





### Challenge

@app.route('/challenge', methods=['POST'])
@jwt_required
def challenge_post():
    data = request.get_json()
    ch = Challenge(title = data.get('title', None), text = data.get('text', None))
    db.session.add(ch)
    gpos = 1
    for goal in data.get('goal', []):
        gl = ChallengeGoal(challenge_id = ch.id,
                            text = goal.get('text', None),
                            category = goal.get('category', None),
                            point = goal.get('point', 0)
                            required = goal.get('required', False),
                            pos=data['goal'][cform].get('pos', str(gpos)))
        db.session.add(gl)
        gpos += 1
    db.session.commit()
    return jsonify(challenge_id=ch.id), 200

@app.route('/challenge', methods=['GET'])
@jwt_required
def challenge_get():
    ch_id = request.get_json()['challenge_id']
    ch = Challenge.query.filter_by(id=ch_id).first()
    goal_data = []
    goals = ChallengeGoal.query.fileter_by(challenge_id=ch_id).order_by(pos).all()
    for gl in goals:
        goal_data.append({
            'text': gl.text,
            'category': gl.category,
            'required': gl.required,
            'point': gl.point})
    return jsonify({
            'title': ch.title,
            'text': ch.text,
            'goals': goal_data
        }), 200


@app.route('/challenge/all')
@jwt_required
def challenge_all():
    ch_all = Challenge.query.all()
    ret = []
    for ch in ch_all:
        ret.append(ch.id)
    return jsonify(ret), 200

@app.route('/challenge/add_goal', methods=['POST'])
@jwt_required
def challenge_add_goal():
    data = request.get_json()
    ch_id = data['challenge_id']
    for goal in data.get('goal', []):
        gl = ChallengeGoal(challenge_id = ch.id,
                            text = goal.get('text', None),
                            category = goal.get('category', None),
                            required = goal.get('required', False)
                            pos = goal.get('pos', 'ZZZ'))
        db.session.add(gl)
    db.session.commit()

### Main

from werkzeug.middleware.dispatcher import DispatcherMiddleware

app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/api": app})

if __name__ == '__main__':
   app.run('0.0.0.0', 5080)


