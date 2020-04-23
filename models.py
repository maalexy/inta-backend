from manage import db, app

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    password = db.Column(db.String)
    email = db.Column(db.String)

    university_id = db.Column(db.Integer)
    activity = db.Column(db.String)
    group = db.Column(db.String)

    def __repr__(self):
        return '[{}]:{}/{}/{}'.format(self.id.__repr__(), self.username.__repr__(), self.password.__repr__(), self.email.__repr__())

class UserContact(db.Model):
    __tablename__ = 'user_contacts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    form = db.Column(db.String)
    address = db.Column(db.String)

class University(db.Model):
    __tablename__ = 'university'

    id = db.Column(db.Integer, primary_key=True)
    short = db.Column(db.String)
    full = db.Column(db.String)
