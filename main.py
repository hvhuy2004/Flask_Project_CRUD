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
# Quan hệ class và student:
class Student_Class(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id_class'), nullable=True)
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


# Admin get all user
@app.route('/admin/get-all-user', methods=['GET', 'POST'])
def adminGetAllUser():
    users = User.query.filter_by(role='user').all()
    return render_template('admin/all-user.html', title="Approve User", users = users)


# Admin approve user
@app.route('/admin/approve-user/<int:id>')
def approveUser(id):
    User.query.filter_by(role='user').filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approved successfully', 'success')
    return redirect('/admin/get-all-user')

# Admin unapprove user
@app.route('/admin/unapprove-user/<int:id>')
def unapproveUser(id):
    User.query.filter_by(role='user').filter_by(id=id).update(dict(status=0))
    db.session.commit()
    flash('Unapproved successfully', 'success')
    return redirect('/admin/get-all-user')

# Admin change pasword
@app.route('/admin/change-admin-password', methods=["GET", "POST"])
def change_admin_password():
    if not session.get("user_id"):
        return redirect("/admin")
    admin = User.query.get(session.get("user_id"))
    if request.method == "GET":
        return render_template('admin/change-password.html', title="Admin Dashboard", users = admin)
    else:
        old_password = request.form.get('old_password')
        password = request.form.get('password')
        
        if old_password == "" or password == "":
            flash('Please fill all fields', 'danger')
            return redirect('/user/change-password')
        
        if bcrypt.check_password_hash(admin.password, old_password):  # Kiểm tra mật khẩu cũ
            hash_password = bcrypt.generate_password_hash(password, 10)
            admin.password = hash_password  # Cập nhật mật khẩu
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect('/admin/dashboard')  # Chuyển hướng đến dashboard
        else:
            flash('Invalid old password', 'danger')
            return redirect('/admin/change-password')

# Admin all class
@app.route('/admin/class/all')
def get_all_class():
    if not session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin')
    classes = Class.query.join(Subject, Class.id_subject == Subject.id_subject).add_column(Subject.name.label("subject_name")).all()

    return render_template("/admin/all-class.html", title="All Class", classes = classes)
    
# Admin all subject
@app.route('/admin/subject/all')
def get_all_subject():
    if not session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin')
    subjects = Subject.query.all()
    return render_template("/admin/all-subject.html", title="All Subject", subjects = subjects)


# Thêm class
@app.route('/admin/class/add', methods = ["POST", "GET"])
def add_class():
    subjects = Subject.query.all()
    if not session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin')
    if request.method == "GET":
        return render_template("/admin/add-class.html", title="Add Class", subjects = subjects)
    else:
        class_name = request.form.get('class_name')
        subject_id = request.form.get('subject_id')
        if class_name == "" or subject_id == "":
            flash('please fill all fields')
            return redirect('admin/class/add')
        else:
            nclass = Class(name = class_name, id_subject = subject_id)
            db.session.add(nclass)
            db.session.commit()
            flash('Create class success')
            return redirect('/admin/class/all')
        

#Thêm subject
@app.route("/admin/subject/add", methods = ["GET", "POST"])
def add_subject():
    if not session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin')
    if request.method == "GET":
        return render_template("/admin/add-subject.html", title="Add Subject")
    else:
        class_name = request.form.get('class_name')
        if class_name == "":
            flash('please fill all fields')
            return redirect('/admin/subject/add')
        else:
            nclass = Subject(name = class_name)
            db.session.add(nclass)
            db.session.commit()
            flash('Create class success')
            return redirect('/admin/subject/all')
        

@app.route('/admin/class')
def get_students_in_class():
    if not session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin')
    id = request.args.get('id', type=int)
    print(id)

    # Lấy thông tin lớp từ bảng Class
    class_info = Class.query.get(id)

    if id is None:
        flash("class_id is required")
        return redirect("/admin/class/all")
    students = db.session.query(User).join(Student_Class, User.id == Student_Class.user_id).filter(Student_Class.class_id == id).add_column(Student_Class.id.label("relative_id")).all()
    print(students)
    return render_template("/admin/class's_student.html", class_id = id, class_name = class_info.name,  users = students)



@app.route('/admin/class/students/add', methods=['GET', 'POST'])
def add_student_to_class():
    # Kiểm tra nếu người dùng chưa đăng nhập hoặc không phải là admin
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect('/admin')

    # Lấy class_id từ URL
    class_id = request.args.get('class_id', type=int)

    
    # Lấy thông tin lớp từ bảng Class
    class_info = Class.query.get(class_id)

    # Nếu là yêu cầu POST
    if request.method == 'POST':
        student_id = request.form.get('student_id')

        if student_id:
            # Kiểm tra nếu sinh viên tồn tại
            student = User.query.get(student_id)
            if student:
                # Thêm sinh viên vào lớp
                new_entry = Student_Class(user_id=student.id, class_id=class_id)
                db.session.add(new_entry)
                db.session.commit()
                flash('Student added to class successfully.', 'success')
                return redirect(f'/admin/class?id={class_id}')

    # Lấy danh sách sinh viên có status = 1 và chưa có trong lớp
    students_in_class = db.session.query(Student_Class.user_id).filter_by(class_id=class_id).all()
    student_ids_in_class = [student[0] for student in students_in_class]

    # Lọc danh sách sinh viên có status = 1 và chưa có trong lớp
    students = User.query.filter(User.status == 1, User.role == 'user', User.id.notin_(student_ids_in_class)).all()

    return render_template('admin/add_student.html', students=students, class_id=class_id )

    

# Xóa user khỏi lớp 
@app.route('/admin/students/remove', methods=['GET'])
def remove_student_from_class():
    relative_id = request.args.get('id', type=int)

    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect('/admin')

    if relative_id:
        student_class = Student_Class.query.get(relative_id)
        if student_class:
            db.session.delete(student_class)
            db.session.commit()
            flash('Student removed from class successfully.', 'success')
        else:
            flash('Student not found in the class.', 'danger')

    class_id = request.args.get('class_id', type=int)
    return redirect(f'/admin/class?id={class_id}')

    


if __name__ == '__main__':
    app.run(debug=True)
