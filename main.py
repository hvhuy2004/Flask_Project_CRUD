from flask import Flask, render_template, request, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///ums.sqlite"
app.config["SECRET_KEY"] = 'c782718b0501dc77c66148d9'
app.config["SESSION_PARMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)

# User class
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    edu = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}", "{self.fname}", "{self.lname}", "{self.email}", "{self.edu}", "{self.username}", "{self.status}")'

# Tạo bảng trong cơ sở dữ liệu
with app.app_context():
    db.create_all()
    print("Database and tables created.")

# Main index file
@app.route('/')
def index():
    return render_template('index.html', title="")

# Admin login
@app.route('/admin/')
def adminIndex():
    return render_template('admin/index.html', title="Admin Login")

# -------------------user area-------------------

# User login 
@app.route('/user/', methods=['POST', 'GET'])
def userIndex():
    if session.get('user_id'):
        return redirect('/user/dashboard')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        users = User.query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password, password):
            if users.status == 0:
                flash('Your account is not approved by Admin', 'danger')
                return redirect('/user/')
            else:
                session['user_id'] = users.id
                session['username'] = users.username
                flash('Login Successfully', 'success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and Password', 'danger')
            return redirect('/user/')

    return render_template('user/index.html', title="User Login")



def userIndex():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    
    if request.method == 'POST':
    
        # get the name of the field
        email = request.form.get('email')
        password = request.form.get('password')

        # check user exist in this email or not
        users = User().query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password, password):
            
            # check the admin approved your account or not
            is_approve = User.query.filter_by(id=users.id).first()
            # first return the is_approve:
            if is_approve.status ==0:
                flash('Your account is not approved by Admin', 'danger')
                return redirect('/user/')
            else:
                session['user_id'] = users.id
                session['username'] = users.username
                flash('Login Successfully', 'success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and Password', 'danger')
            return redirect('/user/')

    else:
        return render_template('user/index.html', title="User Login")

# User register
@app.route('/user/signup', methods=['POST', 'GET'])
def userSignup():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method == 'POST':
        # Get all input fields
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')
        password = request.form.get('password')

        # Check if all fields are filled
        if not all([fname, lname, email, password, username, edu]):
            flash('Please fill all the fields', 'danger')
            return redirect('/user/signup')
        else:
            # Check if the email already exists
            is_email = User.query.filter_by(email=email).first()
            if is_email:
                flash('Email already exists', 'danger')
                return redirect('/user/signup')
            else:
                # Hash the password and create a new user
                hash_password = bcrypt.generate_password_hash(password, 10).decode('utf-8')
                user = User(fname=fname, lname=lname, email=email, password=hash_password, edu=edu, username=username)
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully! Admin will approve your account.', 'success')
                return redirect('/user/')

    else:
        return render_template('user/signup.html', title="User Signup")


# User dashboard
@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/user/')
    return render_template('user/dashboard.html', title="User Dashboard")

# User logout
@app.route('/user/logout')
def userLogout():
    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        session.clear()
        flash('Logout successfully', 'success')
        return redirect('/user/')

# Route để xem tất cả tài khoản
@app.route('/admin/users')
def view_users():
    users = User.query.all()  # Lấy tất cả người dùng từ cơ sở dữ liệu
    return render_template('admin/view_users.html', users=users, title="View Users")


if __name__ == '__main__':
    app.run(debug=True)
