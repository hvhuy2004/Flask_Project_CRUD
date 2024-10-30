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
    student_code = db.Column(db.String(50), nullable=True)  
    birth_year = db.Column(db.Integer, nullable=True)       
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)  # Thêm cột role
    status = db.Column(db.Integer, default=0, nullable=False)
    id_class = db.Column(db.Integer, db.ForeignKey('class.id_class'), nullable=True)

    def __repr__(self):
        return f'User("{self.id}", "{self.fname}", "{self.lname}", "{self.email}", "{self.username}", "{self.role}", "{self.status}", "{self.student_code}", "{self.birth_year}")'

# Class class
class Class(db.Model):
    id_class = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    id_subject = db.Column(db.Integer, db.ForeignKey('subject.id_subject'), nullable=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# Subject class
class Subject(db.Model):
    id_subject = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    id_class = db.Column(db.Integer, db.ForeignKey('class.id_class'), nullable=True)


# Tạo bảng trong cơ sở dữ liệu
with app.app_context():
    db.create_all()
    print("Database and tables created.")

# Main index file
@app.route('/')
def index():
    return render_template('index.html', title="")

# # Admin login
# @app.route('/admin/')
# def adminIndex():
#     return render_template('admin/index.html', title="Admin Login")

# -------------------user area-------------------

# User login
@app.route('/user/', methods=['POST', 'GET'])
def userIndex():
    if session.get('user_id'):
        return redirect('/user/dashboard')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = User.query.filter_by(username=username).first()
        if users and bcrypt.check_password_hash(users.password, password):
            if users.status == 0:
                flash('Your account is not approved by Admin', 'danger')
                return redirect('/user/')
            elif users.role != 'user':
                flash('You do not have permission to log in', 'danger')
                return redirect('/user/')
            else:
                session['user_id'] = users.id
                session['username'] = users.username
                flash('Login Successfully', 'success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Username and Password', 'danger')
            return redirect('/user/')

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
        birth_year = request.form.get('birth_year')
        student_code = request.form.get('student_code')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if all fields are filled
        if not all([fname, lname, email, password, username, birth_year, student_code]):
            flash('Please fill all the fields', 'danger')
            return redirect('/user/signup')
        else:
            # Check if the email already exists
            is_username = User.query.filter_by(username=username).first()
            is_studentcode = User.query.filter_by(student_code=student_code).first()
            if is_username:
                flash('Username already exists', 'danger')
                return redirect('/user/signup')
            elif is_studentcode:
                flash('Student code already exists', 'danger')
                return redirect('/user/signup')
            else:
                # Hash the password and create a new user
                hash_password = bcrypt.generate_password_hash(password, 10).decode('utf-8')
                user = User(fname=fname, lname=lname, email=email,birth_year=birth_year, student_code = student_code, password=hash_password, username=username)
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
    
    user = User.query.get(session.get('user_id'))
    
    # Kiểm tra nếu role là "user"
    if user.role != "user":
        flash("Access denied: You are not authorized to access this page.", "danger")
        return redirect('/user/')
    
    return render_template('user/dashboard.html', title="User Dashboard", users=user)

# User logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        session.clear()
        flash('Logout successfully', 'success')
        return redirect('/user/')
    

@app.route('/user/change-password', methods=["POST", "GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/user/')
    
    user = User.query.get(session.get('user_id'))
    
    # Kiểm tra nếu role là "user"
    if user.role != "user":
        flash("Access denied: You are not authorized to access this page.", "danger")
        return redirect('/user/')
    
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        password = request.form.get('password')
        
        if old_password == "" or password == "":
            flash('Please fill all fields', 'danger')
            return redirect('/user/change-password')
        
        if bcrypt.check_password_hash(user.password, old_password):  # Kiểm tra mật khẩu cũ
            hash_password = bcrypt.generate_password_hash(password, 10)
            user.password = hash_password  # Cập nhật mật khẩu
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect('/user/dashboard')  # Chuyển hướng đến dashboard
        else:
            flash('Invalid old password', 'danger')
            return redirect('/user/change-password')
    else:
        return render_template('user/change-password.html', title="Change Password")


@app.route('/user/update-profile', methods=['POST', 'GET'])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/user/')
    
    user = User.query.get(session.get('user_id'))
    
    # Kiểm tra nếu role là "user"
    if user.role != "user":
        flash("Access denied: You are not authorized to access this page.", "danger")
        return redirect('/user/')
    
    if request.method == 'POST':
        # Get all input fields
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        birth_year = request.form.get('birth_year')
        student_code = request.form.get('student_code')
        username = request.form.get('username')
        # Check if all fields are filled
        if not all([fname, lname, email, username]):
            flash('Please fill all the fields', 'danger')
            return redirect('/user/update-profile')
        else:
            User.query.filter_by(id=user.id).update(dict(fname=fname, lname=lname, email=email, username=username, birth_year=birth_year, student_code=student_code))
            db.session.commit()
            flash('Profile updated successfully', 'success')
            return redirect('/user/update-profile')
    else:
        return render_template('user/update-profile.html', title="Update Profile", users=user)


# -------------------admin area-------------------

# Admin login 
@app.route('/admin/', methods=['POST', 'GET'])
def adminIndex():
    # Nếu người dùng đã đăng nhập và có quyền admin
    if session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin/dashboard')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        admin_user = User.query.filter_by(username=username).first()
        if admin_user and bcrypt.check_password_hash(admin_user.password, password):
            if admin_user.role != 'admin':
                flash('Access denied: Admin privileges required.', 'danger')
                return redirect('/admin/')
            elif admin_user.status == 0:
                flash('Your admin account is not approved.', 'danger')
                return redirect('/admin/')
            else:
                session['user_id'] = admin_user.id
                session['username'] = admin_user.username
                session['role'] = admin_user.role
                flash('Admin login successful', 'success')
                return redirect('/admin/dashboard')
        else:
            flash('Invalid Username and Password', 'danger')
            return redirect('/admin/')

    return render_template('admin/index.html', title="Admin Login")


@app.route('/admin/dashboard')
def adminDashboard():
    # Kiểm tra xem người dùng có đang đăng nhập và có quyền admin hay không
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect('/admin/')  # Chuyển hướng đến trang đăng nhập admin nếu không đúng
    users = User.query.all()
    return render_template('admin/dashboard.html', title="Admin Dashboard", users=users)

# Admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('user_id'):
        return redirect('/admin/')

    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        session.clear()
        flash('Logout successfully', 'success')
        return redirect('/admin/')


# Route để xem tất cả tài khoản
@app.route('/admin/users')
def view_users():
    users = User.query.all()  # Lấy tất cả người dùng từ cơ sở dữ liệu
    return render_template('admin/view_users.html', users=users, title="View Users")



if __name__ == '__main__':
    app.run(debug=True)
