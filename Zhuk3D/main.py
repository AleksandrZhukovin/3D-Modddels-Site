from flask import Flask, render_template, request, redirect, url_for
from flask_admin import Admin, AdminIndexView
import flask_sqlalchemy
import sqlalchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_security import RoleMixin, UserMixin, Security, SQLAlchemyUserDatastore, current_user
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.fileadmin import FileAdmin
import os.path as op
import os
from threading import Timer

app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = 'salt'
app.config['SECURITY_PASSWORD_HASH'] = 'sha512_crypt'
app.config['SECRET_KEY'] = '1234'
path = op.join(op.dirname(__file__), 'static')
WHOOSH_BASE = os.path.join('shop.db')
db = flask_sqlalchemy.SQLAlchemy(app)

migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

engine = sqlalchemy.create_engine('sqlite:///shop.db')
sqlalchemy.orm.configure_mappers()


class Item(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(30), nullable=False, unique=True)
    type = db.Column(db.String(), nullable=False)
    carousel_id = db.Column(db.Integer(), nullable=False, unique=True)
    path_1 = db.Column(db.String(), nullable=True)
    path_2 = db.Column(db.String(), nullable=True)
    path_3 = db.Column(db.String(), nullable=True)
    path_4 = db.Column(db.String(), nullable=True)
    path_5 = db.Column(db.String(), nullable=True)
    path_6 = db.Column(db.String(), nullable=True)
    path_7 = db.Column(db.String(), nullable=True)
    path_8 = db.Column(db.String(), nullable=True)
    path_9 = db.Column(db.String(), nullable=True)
    path_10 = db.Column(db.String(), nullable=True)
    file_type = db.Column(db.String(), nullable=True)
    file = db.Column(db.String(), nullable=False)
    weight = db.Column(db.Float(), nullable=True)
    description = db.Column(db.Text(500), nullable=False)

    def __repr__(self):
        return self.title


roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
                       )


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(225))
    active = db.Column(db.Boolean())
    hash = db.Column(db.String())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100), unique=True)
    desc = db.Column(db.String(225))


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


class AdminSecurity(ModelView):
    def is_accessible(self):
        return current_user.has_role('admin')

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('security.login', next=request.url))


class HomeAdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.has_role('admin')

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('security.login', next=request.url))


admin = Admin(app, "FlaskApp", url='/', index_view=HomeAdminView('Home'))


@app.route("/")
@app.route("/<int:page>")
def search(page=1):
    per_page = 20
    result = request.args.get('q')
    if result:
        items = Item.query.filter(Item.title.contains(result)).paginate(page, per_page, error_out=False)
    else:
        items = Item.query.paginate(page, per_page, error_out=False)
    return render_template("mai.html", data=items)


@app.route('/transport')
@app.route('/transport/<int:page>')
def transport(page=1):
    per_page = 20
    items = Item.query.filter(Item.type == 'transport').paginate(page, per_page, error_out=False)
    return render_template("transport.html", data=items)


@app.route('/tools')
@app.route('/tools/<int:page>')
def tools(page=1):
    per_page = 20
    items = Item.query.filter(Item.type == 'tool').paginate(page, per_page, error_out=False)
    return render_template("tools.html", data=items)


@app.route('/nature')
@app.route('/nature/<int:page>')
def nature(page=1):
    per_page = 20
    items = Item.query.filter(Item.type == 'nature').paginate(page, per_page, error_out=False)
    return render_template("nature.html", data=items)


@app.route('/characters')
@app.route('/characters/<int:page>')
def characters(page=1):
    per_page = 20
    items = Item.query.filter(Item.type == 'character').paginate(page, per_page, error_out=False)
    return render_template("nature.html", data=items)


@app.route('/furniture')
@app.route('/furniture/<int:page>')
def furniture(page=1):
    per_page = 20
    items = Item.query.filter(Item.type == 'furniture').paginate(page, per_page, error_out=False)
    return render_template("furniture.html", data=items)


@app.route('/buildings')
@app.route('/buildings/<int:page>')
def buildings(page=1):
    per_page = 20
    items = Item.query.filter(Item.type == 'building').paginate(page, per_page, error_out=False)
    return render_template("buildings.html", data=items)


@app.route('/test')
def bil():
    items = Item.query.all()
    # response_url = 'test'
    return render_template('test.html', data=items)


@app.route('/buy/<int:id>')
def item_buy(id):
    item = Item.query.get(id)
    item_ = item.query.filter(Item.id == id)
    return render_template('good_page.html', data=item_)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


def update_data(interval):
    Timer(interval, update_data, [interval]).start()
    _list = Item.query.all()
    title_list = [op.title for op in _list]
    for i in title_list:
        try:
            os.mkdir('static/' + i)
        except FileExistsError:
            pass


def create_user_role(email, password, name, desc):
    user_datastore.create_user(email=email, password=password)
    user = User.query.first()
    User.hash = generate_password_hash(user.password)
    checked_password = check_password_hash(user.hash, user.password)
    user_datastore.create_role(name=name, desc=desc)
    role = Role.query.first()
    user_datastore.add_role_to_user(user, role)


db.create_all()
admin.add_view(FileAdmin(path, '/static/', name='Files'))
admin.add_view(AdminSecurity(Item, db.session))

if __name__ == "__main__":
    update_data(1)
    manager.run()
