from flask import Flask, abort, render_template, request, url_for, redirect, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

# Add a configuration for file uploads
UPLOAD_FOLDER = 'Attachments'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(50), nullable=False)  # Add the author field
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    task_id = db.Column(db.Integer, db.ForeignKey('todo.id'), nullable=False)
    attachment_path = db.Column(db.String(255))
    
    # Add other necessary fields and relationships
    
    def __repr__(self):
        return f'<Comment {self.id}>'

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    owner = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(60), nullable=False, default="New")
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    finished = db.Column(db.DateTime, nullable=True)
    comment_count = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='task', lazy=True, cascade='all, delete-orphan')


    def __repr__(self):
        return '<Task %r>' % self.id

@app.route('/', methods=['POST','GET'])
def index():
    if request.method == 'POST':
        task_content = request.form['content']
        task_owner = request.form['owner']
        task_author = request.form['author']
        if task_content and task_owner and task_author:
            new_task = Todo(content=task_content, owner=task_owner, author=task_author)
            try:
                db.session.add(new_task)
                db.session.commit()
                return redirect('/')
            except:
                return 'Tehere is a issue adding your task, please contact IT department'
        else:
            return 'Task content and owner and author cannot be empty. Please enter all!'
    else:
        tasks = Todo.query.order_by(Todo.date_created).all()
        return render_template('index.html', tasks=tasks)

@app.route('/delete/<int:id>',methods=['GET', 'POST'])
def delete(id):
    task_to_delete = Todo.query.get_or_404(id) #this will try to get first the id if exist if not will pop up 404 error
    if request.method == 'POST':
        try:
            db.session.delete(task_to_delete)
            db.session.commit()
            return redirect('/')
        except:
            return 'There was a problem deleting that task'

@app.route('/task/<int:task_id>')
def view_task(task_id):
    task = Todo.query.get_or_404(task_id)
    return render_template('task_detail.html', task=task)

@app.route('/update_task/<int:task_id>', methods=['GET','POST'])
def update_task(task_id):
    task = Todo.query.get_or_404(task_id)

    if request.method == 'POST':
        new_status = request.form['status']
        task.status = new_status

        if new_status == 'Completed' and task.finished is None:
            # Set finished date if status is set to Completed and finished date is not already set
            task.finished = datetime.utcnow()
        try:
            db.session.commit()
            return redirect('/')
        except Exception as e:
            db.session.rollback()  # Rollback changes if an exception occurs
            return f'There was an issue updating the task status:    {str(e)}'
        
    return render_template('index.html', task=task)

@app.route('/update_owner/<int:task_id>', methods=['GET','POST'])
def update_owner(task_id):
    task = Todo.query.get_or_404(task_id)

    if request.method == 'POST':
        new_owner = request.form['new_owner']
        task.owner = new_owner

        if new_owner is not None and new_owner != '':
            task.owner = new_owner

        try:
            db.session.commit()
            return redirect('/')
        except Exception as e:
            db.session.rollback()  # Rollback changes if an exception occurs
            return f'There was an issue updating the task status:    {str(e)}'
        
    return render_template('index.html', task=task)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/add_task_comment/<int:task_id>', methods=['GET', 'POST'])
def add_task_comment(task_id):
    task = Todo.query.get_or_404(task_id)

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

        task_comment = Comment(content=new_task_comment, author=author, task=task, attachment_path=attachment_path)
        task.comment_count += 1

        try:
            db.session.add(task_comment)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return f'There was an issue adding the comment: {str(e)}'

    # Fetch the task along with its comments
    task_with_comments = Todo.query.options(db.joinedload(Todo.comments)).get_or_404(task_id)

    return render_template('task_detail.html', task=task_with_comments)

@app.route('/download_attachment/<path:filename>')
def download_attachment(filename):
    filename = os.path.basename(filename)
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], secure_filename(filename), as_attachment=True)
    except FileNotFoundError:
        abort(404)

def filter_tasks(query, filter_date, filter_owner):
    if filter_date:
        # Convert the filter_date string to a datetime object
        filter_date = datetime.strptime(filter_date, '%Y-%m-%d').date()
        query = query.filter_by(date_created=filter_date)

    if filter_owner:
        query = query.filter_by(owner=filter_owner)

    return query


if __name__ == '__main__':
    app.run(debug=True)