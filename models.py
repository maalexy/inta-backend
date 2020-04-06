from manage import db, app

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    password = db.Column(db.String())
    email = db.Column(db.String())

    def __repr__(self):
        return '[{}]:{}/{}/{}'.format(self.id.__repr__(), self.username.__repr__(), self.password.__repr__(), self.email.__repr__())