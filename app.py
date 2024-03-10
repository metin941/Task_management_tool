from flask import Flask, abort, render_template, request, url_for, redirect, send_from_directory , flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db',
    'admins': 'sqlite:///admins.db'
}  # New databases for users and admins
app.config['SECRET_KEY'] = 'admin'  # Change this to a secret key of your choice
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#Configuration for file uploads
UPLOAD_FOLDER = 'Attachments'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'cmd', 'bat','rar','zip'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#This part redirects directly to login page 
@app.route('/')#Here goes the webpage main name
def redirect_to_index():
    return redirect(url_for('login'))

# Comment class for Project
class Comment_project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    task_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)  # Update this line
    attachment_path = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<Comment_project {self.id}>'

# Comment class for Task
class Comment_task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)  # Update this line
    attachment_path = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<Comment_task {self.id}>'

#Tasks class
class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    owner = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(60), nullable=False, default="New")
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    finished = db.Column(db.DateTime, nullable=True)
    comment_count = db.Column(db.Integer, default=0)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)  # Update this line
    comments = db.relationship('Comment_task', backref='task', lazy=True, cascade='all, delete-orphan', primaryjoin="Tasks.id == Comment_task.task_id")


    def __repr__(self):
        return '<Task %r>' % self.id

#Projects class
class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    owner = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(60), nullable=False, default="New")
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    finished = db.Column(db.DateTime, nullable=True)
    comment_count = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment_project', backref='project', lazy=True, cascade='all, delete-orphan', primaryjoin="Projects.id == Comment_project.task_id")


    def __repr__(self):
        return '<Project %r>' % self.id

#User class adds new user to users.db file from /register tab
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

#UserLogin class reads from user.db file 
class UserLogin(UserMixin, db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

#Admin User class adds new user to users.db file from /register tab
class AdminUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

#UserLogin class reads from admins.db file 
class AdminLogin(UserMixin, db.Model):
    __bind_key__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
#============================================Registe and Login =============================================================

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_admin_user = AdminLogin.query.filter_by(username=username).first()
        if existing_admin_user:
            return render_template('admin_register.html', error='Admin username already exists. Choose a different one.')

        new_admin_user = AdminLogin(username=username)
        new_admin_user.set_password(password)

        try:
            db.session.add(new_admin_user)
            db.session.commit()
            login_user(new_admin_user)
            return redirect(url_for('login_admin'))
        except Exception as e:
            db.session.rollback()
            return 'Error registering admin user. Please try again.'

    return render_template('admin_register.html', error=None)

#Register page 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = UserLogin.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Username already exists. Choose a different one.')

        new_user = UserLogin(username=username)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            return 'Error registering user. Please try again.'

    return render_template('register.html', error=None)

#Load user uses query.get and reads by ID
@login_manager.user_loader
def load_user(user_id):
    # Check if the user_id is associated with a regular user
    user = UserLogin.query.get(int(user_id))
    if user:
        return user
    
    # If not, check if it corresponds to an admin user
    admin_user = AdminLogin.query.get(int(user_id))
    if admin_user:
        return admin_user
    
    return None  # Return None if the user_id is not found

#Login user , it reads from users.db the user and then checks the password with if statement
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = UserLogin.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('main'))  # Redirect to the 'main' route upon successful login
        else:
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html', error=None)

#Login admin , it reads from users.db the user and then checks the password with if statement
@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin_user = AdminLogin.query.filter_by(username=username).first()

        if admin_user and admin_user.check_password(password):
            login_user(admin_user)
            return redirect(url_for('admin_project'))  # Redirect to the 'admin_project' route upon successful login
        else:
            return render_template('login_admin.html', error='Invalid admin username or password')

    return render_template('login_admin.html', error=None)

#Logout from the Admin page
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
#==============================================================================================================================

@app.route('/main/<int:project_id>', methods=['POST', 'GET'])
@app.route('/main', methods=['POST', 'GET'])
def main(project_id=None):
    if project_id:
        project = Projects.query.get_or_404(project_id)
    else:
        project = None

    if request.method == 'POST':
        if project:
            new_status = request.form.get('status')
            project.status = new_status

            if new_status == 'Completed' and project.finished is None:
                project.finished = datetime.utcnow()

            try:
                db.session.commit()
                return redirect(url_for('main'))
            except Exception as e:
                db.session.rollback()
                return f'There was an issue updating the project status: {str(e)}'

    projects = Projects.query.order_by(Projects.date_created).all()
    return render_template('main.html', projects=projects, selected_project=project)

@app.route('/main_project_details/<int:project_id>')
def main_project_details(project_id):
    # Retrieve the project based on project_id
    project = Projects.query.get_or_404(project_id)
    # Retrieve associated tasks for the project
    tasks = Tasks.query.filter_by(project_id=project_id).all()
    # Add any additional logic you need for displaying project details
    return render_template('main_project_details.html', project=project, tasks=tasks)

@app.route('/main_view_task/<int:task_id>')
def main_view_task(task_id):
    task = Tasks.query.get_or_404(task_id)
    return render_template('task_detail.html', task=task)

@app.route('/main_update_task/<int:task_id>', methods=['POST'])
def main_update_task(task_id):
    task = Tasks.query.get_or_404(task_id)

    if request.method == 'POST':
        new_status = request.form['status']
        task.status = new_status

        if new_status == 'Completed' and task.finished is None:
            # Set finished date if status is set to Completed and finished date is not already set
            task.finished = datetime.utcnow()

        try:
            db.session.commit()
            flash('Task updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'There was an issue updating the task status: {str(e)}', 'danger')

    return redirect(url_for('main_project_details', project_id=task.project_id))

@app.route('/main_add_project_comment/<int:project_id>', methods=['POST'])
def main_add_project_comment(project_id):
    project = Projects.query.get_or_404(project_id)

    if request.method == 'POST':
        new_project_comment = request.form.get('comment_content')
        author = request.form.get('comment-author')  # Use the correct name here

        # Initialize attachment_path to None
        attachment_path = None

        # Check if the post request has the file part
        if 'attachment' in request.files:
            file = request.files['attachment']
            # If the user selects a file and it's allowed, save it
            if file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Save the filename to the database or use it as needed
                attachment_path = os.path.join('Attachments', filename)

        project_comment = Comment_project(content=new_project_comment, author=author, project=project, attachment_path=attachment_path)
        project.comment_count += 1

        try:
            db.session.add(project_comment)
            db.session.commit()
            return redirect(url_for('main_project_details', project_id=project_id))
        except Exception as e:
            db.session.rollback()
            return f'There was an issue adding the comment: {str(e)}'

    # Fetch the project along with its comments
    project_with_comments = Projects.query.options(db.joinedload(Projects.comments)).get_or_404(project_id)

    return render_template('main_project_details', project=project_with_comments)

#=============================================Project==========================================================================
#Admin projects page 
@app.route('/admin_project', methods=['POST', 'GET'])
def admin_project():
    if request.method == 'POST':
        project_content = request.form['content']
        project_owner = request.form['owner']
        project_author = request.form['author']
        if project_content and project_owner and project_author:
            new_project = Projects(content=project_content, owner=project_owner, author=project_author)
            try:
                db.session.add(new_project)
                db.session.commit()
                return redirect(url_for('admin_project'))
            except:
                return 'There is an issue adding your project, please contact the IT department'
        else:
            return 'Project content, owner, and author cannot be empty. Please enter all!'
    else:
        projects = Projects.query.order_by(Projects.date_created).all()
        return render_template('admin_project.html', projects=projects)

#View project opening a new page
@app.route('/project/<int:project_id>')
def view_project(project_id):
    project = Projects.query.get_or_404(project_id)
    return redirect(url_for('project_details', project_id=project_id))

#Delete project
@app.route('/delete/<int:id>', methods=['POST'])
def delete_project(id):
    project_to_delete = Projects.query.get_or_404(id)

    try:
        # Delete all tasks associated with the project
        tasks_to_delete = Tasks.query.filter_by(project_id=id).all()
        for task in tasks_to_delete:
            db.session.delete(task)

        # Delete the project itself
        db.session.delete(project_to_delete)
        db.session.commit()
        flash('Project and associated tasks deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'There was a problem deleting the project and tasks: {str(e)}', 'danger')

    return redirect(url_for('admin_project'))

#Update project , updates project status 
@app.route('/update_project/<int:project_id>', methods=['POST'])
def update_project(project_id):
    project = Projects.query.get_or_404(project_id)

    if request.method == 'POST':
        new_status = request.form['status']
        project.status = new_status

        if new_status == 'Completed' and project.finished is None:
            project.finished = datetime.utcnow()

        try:
            db.session.commit()
            return redirect(url_for('admin_project'))
        except Exception as e:
            db.session.rollback()
            return f'There was an issue updating the project status: {str(e)}'

    return render_template('admin_project.html', project=project)

#Update owner of the project
@app.route('/update_owner_project/<int:project_id>', methods=['POST'])
def update_owner_project(project_id):
    project = Projects.query.get_or_404(project_id)

    if request.method == 'POST':
        new_owner = request.form['new_owner']
        project.owner = new_owner

        try:
            db.session.commit()
            return redirect(url_for('admin_project'))
        except Exception as e:
            db.session.rollback()
            return f'There was an issue updating the project owner: {str(e)}'

    return render_template('admin_project.html', project=project)

#Add project comments
@app.route('/add_project_comment/<int:project_id>', methods=['POST'])
def add_project_comment(project_id):
    project = Projects.query.get_or_404(project_id)

    if request.method == 'POST':
        new_project_comment = request.form.get('comment_content')
        author = request.form.get('comment-author')  # Use the correct name here

        # Initialize attachment_path to None
        attachment_path = None

        # Check if the post request has the file part
        if 'attachment' in request.files:
            file = request.files['attachment']
            # If the user selects a file and it's allowed, save it
            if file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Save the filename to the database or use it as needed
                attachment_path = os.path.join('Attachments', filename)

        project_comment = Comment_project(content=new_project_comment, author=author, project=project, attachment_path=attachment_path)
        project.comment_count += 1

        try:
            db.session.add(project_comment)
            db.session.commit()
            return redirect(url_for('project_details', project_id=project_id))
        except Exception as e:
            db.session.rollback()
            return f'There was an issue adding the comment: {str(e)}'

    # Fetch the project along with its comments
    project_with_comments = Projects.query.options(db.joinedload(Projects.comments)).get_or_404(project_id)

    return render_template('project_details', project=project_with_comments)

@app.route('/project_details/<int:project_id>')
def project_details(project_id):
    # Retrieve the project based on project_id
    project = Projects.query.get_or_404(project_id)
    # Retrieve associated tasks for the project
    tasks = Tasks.query.filter_by(project_id=project_id).all()
    # Add any additional logic you need for displaying project details
    return render_template('project_details.html', project=project, tasks=tasks)

#==========================================================================================================

#============================================Tasks=========================================================

#Admin task page 
@app.route('/add_project_task/<int:project_id>', methods=['POST'])
def add_project_task(project_id):
    if request.method == 'POST':
        task_content = request.form['content']
        task_owner = request.form['owner']
        task_author = request.form['author']

        if task_content and task_owner and task_author:
            # Retrieve the project based on project_id
            project = Projects.query.get_or_404(project_id)

            # Create a new task related to the project
            new_task = Tasks(content=task_content, owner=task_owner, author=task_author, project_id=project_id)

            try:
                db.session.add(new_task)
                db.session.commit()
                # Replace 'display_project_details' with the correct endpoint for displaying project details
                return redirect(url_for('project_details', project_id=project_id))
            except Exception as e:
                return f'There is an issue adding your task. Error: {str(e)}. Please contact the IT department'
        else:
            return 'Task content, owner, and author cannot be empty. Please enter all!'
    else:
        # Handle the case when the request method is not POST
        return redirect(url_for('project_details', project_id=project_id))

#Delete task 
@app.route('/delete_task/<int:id>', methods=['POST'])
def delete_task(id):
    task_to_delete = Tasks.query.get_or_404(id)
    project_id = task_to_delete.project_id  # Get the project ID before deletion

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        flash('Task deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'There was a problem deleting the task: {str(e)}', 'danger')

    return redirect(url_for('project_details', project_id=project_id))

#View task opening a new page
@app.route('/task/<int:task_id>')
def view_task(task_id):
    task = Tasks.query.get_or_404(task_id)
    return render_template('task_detail.html', task=task)

#Update tasks , updates task status 
@app.route('/update_task/<int:task_id>', methods=['POST'])
def update_task(task_id):
    task = Tasks.query.get_or_404(task_id)

    if request.method == 'POST':
        new_status = request.form['status']
        task.status = new_status

        if new_status == 'Completed' and task.finished is None:
            # Set finished date if status is set to Completed and finished date is not already set
            task.finished = datetime.utcnow()

        try:
            db.session.commit()
            flash('Task updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'There was an issue updating the task status: {str(e)}', 'danger')

    return redirect(url_for('project_details', project_id=task.project_id))

#Update owner of the task
@app.route('/update_owner/<int:task_id>', methods=['POST'])
def update_owner(task_id):
    task = Tasks.query.get_or_404(task_id)

    if request.method == 'POST':
        new_owner = request.form['new_owner']
        task.owner = new_owner

        if new_owner is not None and new_owner != '':
            task.owner = new_owner

        try:
            db.session.commit()
            flash('Owner updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'There was an issue updating the task owner: {str(e)}', 'danger')

    return redirect(url_for('project_details', project_id=task.project_id))

#Allowed file in the task comment section
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#Task comment 
@app.route('/add_task_comment/<int:task_id>', methods=['GET', 'POST'])
def add_task_comment(task_id):
    task = Tasks.query.get_or_404(task_id)

    if request.method == 'POST':
        new_task_comment = request.form['comment_content']
        author = request.form['comment-author']  # Use the correct name here
        # Initialize attachment_path to None
        attachment_path = None

        # Check if the post request has the file part
        if 'attachment' in request.files:
            file = request.files['attachment']
            # If the user selects a file and it's allowed, save it
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Save the filename to the database or use it as needed
                attachment_path = os.path.join('Attachments', filename)

        task_comment = Comment_task(content=new_task_comment, author=author, task=task, attachment_path=attachment_path)
        task.comment_count += 1

        try:
            db.session.add(task_comment)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return f'There was an issue adding the comment: {str(e)}'

    # Fetch the task along with its comments
    task_with_comments = Tasks.query.options(db.joinedload(Tasks.comments)).get_or_404(task_id)

    return render_template('task_detail.html', task=task_with_comments)

#Download attachments from the added comments (Attachments folder)
@app.route('/download_attachment/<path:filename>')
def download_attachment(filename):
    filename = os.path.basename(filename)
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], secure_filename(filename), as_attachment=True)
    except FileNotFoundError:
        abort(404)
#====================================================================================================================================
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0)