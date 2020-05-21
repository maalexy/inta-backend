from manage import db, app

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    name = db.Column(db.String)
    password = db.Column(db.String)
    email = db.Column(db.String)

    university_id = db.Column(db.Integer)
    activity = db.Column(db.String)
    group = db.Column(db.String)

    def __repr__(self):
        return '[{}]:{}/{}/{}'.format(self.id.__repr__(), self.username.__repr__(), self.password.__repr__(), self.email.__repr__())

class UserContact(db.Model):
    __tablename__ = 'user_contact'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    form = db.Column(db.String)
    address = db.Column(db.String)

class University(db.Model):
    __tablename__ = 'university'

    id = db.Column(db.Integer, primary_key=True)
    university = db.Column(db.String)


class Challenge(db.Model):
    __tablename__ = 'challenge'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    text = db.Column(db.String)

class ChallengeGoal(db.Model):
    __tablename__= 'challenge_goal'

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer)
    text = db.Column(db.String)
    category = db.Column(db.String)
    required = db.Column(db.Boolean)
    position = db.Column(db.Integer)

