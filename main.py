from flask import Flask, render_template, request, flash, redirect, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt
from sqlalchemy import or_
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
    birth_year = db.Column(db.Date, nullable=True)       
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)  # Thêm cột role
    status = db.Column(db.Integer, default=0, nullable=False)
    id_class = db.Column(db.Integer, db.ForeignKey('class.id_class'), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)  # Thêm cột avatar

    def generate_student_code(self):
        current_year = datetime.now().year
        year_suffix = str(current_year)[2:]  # Lấy 2 chữ số cuối của năm
        max_id = db.session.query(User.id).order_by(User.id.desc()).first()
        student_count = max_id[0] + 1 if max_id else 1
        batch_number = (student_count // 10000) + 100  # Mỗi 10.000 sinh viên, mã số sẽ tăng thêm 1
        student_number = student_count % 10000  # Số thứ tự sinh viên, bắt đầu từ 0000
        student_code = f"{batch_number:03}{year_suffix}{student_number:04}"
        return student_code

    def __repr__(self):
        return f'User("{self.id}", "{self.fname}", "{self.lname}", "{self.email}", "{self.username}", "{self.role}", "{self.status}", "{self.student_code}", "{self.birth_year}", "{self.avatar}")'

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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id_class'), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)  # 0: Pending, 1: Approved

# Tạo bảng trong cơ sở dữ liệu
with app.app_context():
    db.create_all()
    print("Database and tables created.")

# # Main index file
# @app.route('/')
# def index():
#     return render_template('index.html', title="")

# # Admin login
# @app.route('/admin/')
# def adminIndex():
#     return render_template('admin/index.html', title="Admin Login")

# -------------------user area-------------------

# User login
@app.route('/', methods=['POST', 'GET'])
def userIndex():
    if session.get('user_id'):
        if session.get('role') == 'admin':
            return redirect('/admin/class/')
        else:
            return redirect('/user/dashboard')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = User.query.filter_by(username=username).first()
        if users and bcrypt.check_password_hash(users.password, password):
            if users.status == 0:
                flash('Your account is not approved by Admin', 'danger')
                return redirect('/')
            elif users.role != 'user':
                session['user_id'] = users.id
                session['username'] = users.username
                session['role'] = users.role
                flash('Login Successfully', 'success')
                return redirect('/admin/class/')
            else:
                session['user_id'] = users.id
                session['username'] = users.username
                flash('Login Successfully', 'success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Username and Password', 'danger')
            return redirect('/')

    return render_template('/index.html', title="User Login")






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
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if all fields are filled
        if not all([fname, lname, email, password, username, birth_year]):
            flash('Please fill all the fields', 'danger')
            return redirect('/user/signup')

        # Convert birth_year to date
        try:
            birth_year_date = datetime.strptime(birth_year, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format for birth year. Please use YYYY-MM-DD.', 'danger')
            return redirect('/user/signup')

        # Check if the email or username already exists
        is_username = User.query.filter_by(username=username).first()
        if is_username:
            flash('Username already exists', 'danger')
            return redirect('/user/signup')

        # Generate student code
        new_user = User(fname=fname, lname=lname, email=email, username=username, password=password)
        new_user.birth_year = birth_year_date  # Set the birth year

        # Sinh mã số sinh viên tự động
        new_user.student_code = new_user.generate_student_code()

        # Hash the password
        hash_password = bcrypt.generate_password_hash(password, 10).decode('utf-8')
        new_user.password = hash_password  # Set hashed password

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Admin will approve your account.', 'success')
        return redirect('/')
    return render_template('/signup.html', title="User Signup")



# User dashboard
@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/')
    
    user = User.query.get(session.get('user_id'))
    
    # Kiểm tra nếu role là "user"
    if user.role != "user":
        flash("Access denied: You are not authorized to access this page.", "danger")
        return redirect('/')
    
    return render_template('user/dashboard.html', title="User Dashboard", users=user)

# User logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/')
    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        session['role'] = None
        session.clear()
        flash('Logout successfully', 'success')
        return redirect('/')
    

@app.route('/user/change-password', methods=["POST", "GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/')
    
    user = User.query.get(session.get('user_id'))
    
    # Kiểm tra nếu role là "user"
    if user.role != "user":
        flash("Access denied: You are not authorized to access this page.", "danger")
        return redirect('/')
    
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


def generate_filename(filename):
    # Lấy phần mở rộng của file
    ext = os.path.splitext(filename)[1]
    # Tạo tên file mới bằng UUID
    new_filename = f"{uuid.uuid4().hex}{ext}"
    return new_filename

from datetime import datetime

@app.route('/user/update-profile', methods=['POST', 'GET'])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/')

    user = User.query.get(session.get('user_id'))

    if user.role != "user":
        flash("Access denied: You are not authorized to access this page.", "danger")
        return redirect('/')

    if request.method == 'POST':
        # Lấy dữ liệu từ form
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        birth_year = request.form.get('birth_year')
        student_code = request.form.get('student_code')
        username = request.form.get('username')
        avatar_file = request.files.get('avatar')  # Lấy file avatar từ form

        # Chuyển birth_year thành kiểu date
        if birth_year:
            try:
                birth_year_date = datetime.strptime(birth_year, '%Y-%m-%d').date()
            except ValueError:
                flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
                return redirect('/user/update-profile')
        else:
            birth_year_date = None

        # Kiểm tra các trường bắt buộc
        if not all([fname, lname, email, username]):
            flash('Please fill all the fields', 'danger')
            return redirect('/user/update-profile')

        # Xử lý và lưu file ảnh
        if avatar_file and allowed_file(avatar_file.filename):
            filename = secure_filename(avatar_file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            avatar_file.save(file_path)  # Lưu file vào thư mục uploads
            user.avatar = filename  # Lưu tên file vào cơ sở dữ liệu
        elif avatar_file:
            flash("Invalid file type. Only JPG, JPEG, and PNG are allowed.", "danger")
            return redirect('/user/update-profile')

        # Cập nhật các trường khác vào cơ sở dữ liệu
        user.fname = fname
        user.lname = lname
        user.email = email
        user.username = username
        user.birth_year = birth_year_date
        user.student_code = student_code

        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect('/user/update-profile')

    return render_template('user/update-profile.html', title="Update Profile", users=user)
    
# người dùng xem lớp của mình
@app.route('/user/classes/<int:user_id>', methods=['GET'])
def user_classes(user_id):
    # Lấy thông tin người dùng
    user = User.query.get_or_404(user_id)
    
    # Lấy danh sách các lớp người dùng tham gia, bao gồm cả tên môn học
    classes = db.session.query(Class, Subject.name.label('subject_name')) \
        .join(Subject, Class.id_subject == Subject.id_subject) \
        .join(Student_Class, Student_Class.class_id == Class.id_class) \
        .filter(Student_Class.user_id == user_id).filter(Student_Class.status == 1).all()
    
    # Trả về template với thông tin các lớp và môn học
    return render_template('user/classes.html', user=user, classes=classes)


# người dùng xem sinh viên trong lớp mình
@app.route('/class/students/<int:class_id>', methods=['GET'])
def class_students(class_id):
    # Lấy thông tin lớp
    class_info = Class.query.get_or_404(class_id)
    
    # Lấy danh sách sinh viên thuộc lớp này
    students = db.session.query(User).join(Student_Class).filter(Student_Class.class_id == class_id).all()
    
    return render_template('user/students.html', class_info=class_info, students=students)



# Sinh viên đăng kí vào 1 lớp
@app.route('/user/classes/available', methods=['GET'])
def available_classes():
    if not session.get('user_id'):
        flash("You need to log in to view available classes.", "danger")
        return redirect('/')

    user_id = session.get('user_id')

    # Lấy danh sách các lớp mà sinh viên đã đăng ký và trạng thái duyệt
    registered_classes = db.session.query(Student_Class.class_id, Student_Class.status) \
        .filter(Student_Class.user_id == user_id) \
        .all()

    # Truy vấn tất cả các lớp và môn học liên quan
    available_classes = db.session.query(Class, Subject.name.label('subject_name')) \
        .outerjoin(Subject, Class.id_subject == Subject.id_subject) \
        .all()

    # Đánh dấu trạng thái đăng ký
    class_list = []
    registered_dict = {c: status for c, status in registered_classes}  # Chuyển thành dict để tra cứu nhanh

    for class_info, subject_name in available_classes:
        if class_info.id_class in registered_dict:  # Nếu đã đăng ký
            if registered_dict[class_info.id_class] == 0:  # Trạng thái chưa duyệt
                is_registered = True
            else:  # Trạng thái đã duyệt, bỏ qua
                continue
        else:  # Nếu chưa đăng ký
            is_registered = False

        # Thêm vào danh sách
        class_list.append((class_info, subject_name, is_registered))

    return render_template('user/available_classes.html', classes=class_list)



@app.route('/user/classes/register/<int:class_id>', methods=['POST'])
def register_class(class_id):
    if not session.get('user_id'):
        flash("You need to log in to register for a class.", "danger")
        return redirect('/')

    user_id = session.get('user_id')

    # Kiểm tra xem đã đăng ký trước đó hay chưa
    existing_registration = Student_Class.query.filter_by(user_id=user_id, class_id=class_id).first()
    if existing_registration:
        flash("You have already registered for this class.", "warning")
        return redirect('/user/classes/available')

    # Tạo yêu cầu đăng ký mới
    new_registration = Student_Class(user_id=user_id, class_id=class_id)
    db.session.add(new_registration)
    db.session.commit()
    flash("Class registration successful.", "success")
    return redirect('/user/classes/available')


@app.route('/user/classes/unregister/<int:class_id>', methods=['POST'])
def unregister_class(class_id):
    if not session.get('user_id'):
        flash("You need to log in to unregister from a class.", "danger")
        return redirect('/')

    user_id = session.get('user_id')

    # Tìm đăng ký và xóa
    existing_registration = Student_Class.query.filter_by(user_id=user_id, class_id=class_id).first()
    if not existing_registration:
        flash("You are not registered for this class.", "warning")
        return redirect('/user/classes/available')

    db.session.delete(existing_registration)
    db.session.commit()
    flash("Unregistered from class successfully.", "success")
    return redirect('/user/classes/available')



# -------------------admin area-------------------

# Admin login 
@app.route('/admin/', methods=['POST', 'GET'])
def adminIndex():
    # Nếu người dùng đã đăng nhập và có quyền admin
    if session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin/class/')

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
                return redirect('/admin/class/')
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
        return redirect('/')
    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        session['role'] = None
        session.clear()
        flash('Logout successfully', 'success')
        return redirect('/')


# Admin get all user
@app.route('/admin/get-all-user', methods=['GET', 'POST'])
def adminGetAllUser():
    if request.method == 'POST':
        search = request.form.get('search')
        users = User.query.filter_by(role='user').filter(
            or_(User.fname.like('%' + search + '%'), User.lname.like('%' + search + '%'))
        ).all()
        return render_template('admin/all-user.html', title="Approve User", users = users, search = search)
        
    else:
        search = ''
        users = User.query.filter_by(role='user').all()
        return render_template('admin/all-user.html', title="Approve User", users = users, search=search)


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
            return redirect('/admin/change-password')
        
        if bcrypt.check_password_hash(admin.password, old_password):  # Kiểm tra mật khẩu cũ
            hash_password = bcrypt.generate_password_hash(password, 10)
            admin.password = hash_password  # Cập nhật mật khẩu
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect('/admin/class/')  # Chuyển hướng đến dashboard
        else:
            flash('Invalid old password', 'danger')
            return redirect('/admin/change-password')

# Admin all class
@app.route('/admin/class/')
def get_all_class():
    if not session.get('user_id') and session.get('role') == 'admin':
        return redirect('/admin')
    classes = Class.query.join(Subject, Class.id_subject == Subject.id_subject).add_column(Subject.name.label("subject_name")).all()

    return render_template("/admin/all-class.html", title="All Class", classes = classes)



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
            return redirect('/admin/class/')
        

        

@app.route('/admin/class')
def get_students_in_class():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect('/admin')
    id = request.args.get('id', type=int)
    print(id)

    # Lấy thông tin lớp từ bảng Class
    class_info = Class.query.get(id)

    if id is None:
        flash("class_id is required")
        return redirect("/admin/class/")
    
    # Lấy danh sách sinh viên có status = 1 trong bảng Student_Class
    students = db.session.query(User).join(Student_Class, User.id == Student_Class.user_id).filter(
        Student_Class.class_id == id,
        Student_Class.status == 1  # Chỉ lấy những sinh viên có status = 1
    ).add_column(Student_Class.id.label("relative_id")).all()

    print(students)
    return render_template("/admin/class's_student.html", class_id=id, class_name=class_info.name, users=students)


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
                new_entry = Student_Class(user_id=student.id, class_id=class_id, status = 1)
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

    
# Xóa 1 lớp 
@app.route('/admin/class/delete/<int:id>', methods=['POST'])
def delete_class(id):
    # Lấy lớp học cần xóa
    class_to_delete = Class.query.get(id)
    
    # Kiểm tra nếu lớp học tồn tại
    if class_to_delete:
        try:
            # Xóa các bản ghi liên quan trong bảng student_class
            Student_Class.query.filter_by(class_id=id).delete()
            
            # Xóa lớp học trong bảng class
            db.session.delete(class_to_delete)
            db.session.commit()
            
            flash("Class and related entries successfully deleted.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error occurred while deleting the class: {str(e)}", "danger")
    else:
        flash("Class not found.", "warning")
    
    return redirect('/admin/class/')


# Admin hiển thị yêu cầu đăng kí lớp
@app.route('/admin/registration_requests', methods=['GET'])
def registration_requests():
    requests = db.session.query(Student_Class, User, Class, Subject).join(
        User, Student_Class.user_id == User.id
    ).join(
        Class, Student_Class.class_id == Class.id_class
    ).join(
        Subject, Class.id_subject == Subject.id_subject  # Thêm bảng Subject vào join
    ).filter(Student_Class.status == 0).all()

    return render_template('admin/registration_requests.html', requests=requests)


# Xử lí yêu cầu duyệt vào lớp
@app.route('/admin/registration_requests/<int:request_id>', methods=['POST'])
def process_request(request_id):

    action = request.form.get('action')
    registration_request = Student_Class.query.get(request_id)

    if not registration_request:
        flash("Request not found.", "danger")
        return redirect('/admin/registration_requests')

    if action == 'approve':
        registration_request.status = 1
        flash("Registration approved successfully.", "success")
    elif action == 'reject':
        db.session.delete(registration_request)
        flash("Registration rejected successfully.", "success")
    else:
        flash("Invalid action.", "danger")
        return redirect('/admin/registration_requests')

    db.session.commit()
    return redirect('/admin/registration_requests')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if __name__ == '__main__':
    app.run(debug=True)
