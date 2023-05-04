# import flask modules
from flask import Flask, url_for, render_template, request,redirect,flash, abort, session
import sqlite3
import datetime as dt
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from email_validator import validate_email, EmailNotValidError
from sqlalchemy import create_engine, text
import bcrypt
import pandas as pd
import json
import plotly
import plotly.graph_objs as go
import pymysql

# instance of flask application
app = Flask(__name__)
app.secret_key = 'aef2f0e3683344d0991eaeb046d983eb'
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://gwcuser:gwcuser@34.100.178.136/gwcpmp"
engine = create_engine('mysql+pymysql://gwcuser:gwcuser@34.100.178.136/gwcpmp')
db = SQLAlchemy(app)
app.app_context().push()

#form models
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=250)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')
 
# Database Models
class Users(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Name = db.Column(db.String(250), nullable=False)
    User_Role = db.Column(db.String(250), default='Member', nullable=False)
    Password = db.Column(db.String(250), nullable=False)
    Designation = db.Column(db.String(250), nullable=False)
    Creation_Date = db.Column(db.DateTime(), default=dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30), nullable=False)
    
    def __repr__(self):
        return 'users.id'
    
class Project(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    ProjectName = db.Column(db.String(250), nullable=False)
    ProjectOwner = db.Column(db.String(250), nullable=False)
    ProjectDescription = db.Column(db.Text)
    ProjectManager = db.Column(db.String(250), nullable=False)
    CreatedBy = db.Column(db.String(250), nullable=False)
    Members = db.Column(db.Text)
    StartDate = db.Column(db.Date(), nullable=False)
    EndDate = db.Column(db.Date(), nullable=False)
    CreationDate = db.Column(db.DateTime(), default=dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30), nullable=False)

    def __repr__(self):
        return 'project.id'

class Epic(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    EpicName = db.Column(db.String(250), nullable=False)
    EpicDescription = db.Column(db.Text)
    CreatedBy = db.Column(db.String(250), nullable=False)
    StartDate = db.Column(db.Date(), nullable=False)
    EndDate = db.Column(db.Date(), nullable=False)
    CreationDate = db.Column(db.DateTime(), default=dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30), nullable=False)
    ProjectID = db.Column(db.Integer(), db.ForeignKey('project.id'), nullable=False)

    def __repr__(self):
        return 'epic.id'

class Story(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    StoryName = db.Column(db.String(250), nullable=False)
    StoryDescription = db.Column(db.Text)
    CreatedBy = db.Column(db.String(250), nullable=False)
    StartDate = db.Column(db.Date(), nullable=False)
    EndDate = db.Column(db.Date(), nullable=False)
    CreationDate = db.Column(db.DateTime(), default=dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30), nullable=False)
    EpicID= db.Column(db.Integer(), db.ForeignKey('epic.id'), nullable=False)

    def __repr__(self):
        return 'story.id'

class Subtask(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    SubtaskName = db.Column(db.String(250), nullable=False)
    SubtaskDescription = db.Column(db.Text)
    AssignedTo = db.Column(db.String(250), nullable=False)
    CreatedBy = db.Column(db.String(250), nullable=False)
    StartDate = db.Column(db.Date(), nullable=False)
    EndDate = db.Column(db.Date(), nullable=False)
    CreationDate = db.Column(db.DateTime(), nullable=False)
    Status = db.Column(db.String(250), default='InProgress', nullable=False, )
    StoryID = db.Column(db.Integer(), db.ForeignKey('story.id'), nullable=False)

    def __repr__(self):
        return 'subtask.id'

#Public User Restrictions    
@app.before_request
def require_login():
    allowed_routes = ['login','static', 'show_register']  # add any route that doesn't require login here
    if request.endpoint not in allowed_routes and 'user_id' not in session:
        return redirect(url_for('login'))

#Site User Role Based restrictions
#Member Restrcitions
@app.before_request
def restrict_access_member():
    user_id = session.get('user_id')
    if user_id:
        user = Users.query.filter_by(id=user_id).first()
        if user.User_Role == 'Member':
            restricted_functions = ['add_project', 'add_epic', 'add_story', 'add_subtask', 'update_project', 'update_epic', 'update_story', 'update_subtask', 'delete_subtask', 'delete_story', 'delete_epic','show_projects','project_details','story_details','epic_details', 'show_users','update_user_role']
            if request.endpoint in restricted_functions:
                abort(403)  # Forbidden

#TeamLead Restrcitions
@app.before_request
def restrict_access_teamlead():
    user_id = session.get('user_id')
    if user_id:
        user = Users.query.filter_by(id=user_id).first()
        if user.User_Role == 'Team Lead':
            restricted_functions = ['add_project', 'add_epic', 'add_story', 'update_project', 'update_epic', 'update_story', 'delete_story', 'delete_epic','show_users','update_user_role']
            if request.endpoint in restricted_functions:
                abort(403)  # Forbidden

#Manager Restrcitions
@app.before_request
def restrict_access_manager():
    user_id = session.get('user_id')
    if user_id:
        user = Users.query.filter_by(id=user_id).first()
        if user.User_Role == 'Manager':
            restricted_functions = ['add_project', 'update_project','show_users','update_user_role']
            if request.endpoint in restricted_functions:
                abort(403)  # Forbidden
#Injecting User Info to all pages
@app.context_processor
def inject_user():
    def get_user():
        if 'user_id' in session:
            user = Users.query.get(session['user_id'])
            return user
        return None
    return {'user': get_user()}

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        flash('You have been Logged in Successfully!!', 'success')
        return redirect(url_for('show_user_home'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(Email=email).first()
        
        if user:
            try:
                if bcrypt.checkpw(password.encode('utf-8'), user.Password.encode('utf-8')):
                    session['user_id'] = user.id
                    flash('You have been Logged in Successfully!!', 'success')
                    return redirect(url_for('show_user_home'))
                else:
                    flash('Invalid Email or Password Combination', 'danger')
            except ValueError:
                flash('Invalid Password Hash Format', 'danger')
        else:
            flash('Invalid Email or Password Combination', 'danger')
    
    form = LoginForm()
    return render_template('login_page.html', form=form)


@app.route('/register', methods=['POST','GET'])
def show_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        designation = request.form['designation']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        user_role = request.form['user_role']
        creation_date = dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30)
    
        if not email.endswith('@gwcteq.com'):
            flash('Only gwcteq.com emails are allowed to register', 'warning')
            return redirect(url_for('show_register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'warning')
            return redirect(url_for('show_register'))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user = Users(Email=email, Name=name, Password=hashed_password, Designation=designation, User_Role=user_role, Creation_Date=creation_date)
        db.session.add(user)
        db.session.commit()
        
        flash('You have been Successfully Registered! You can now login!!', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register_page.html')
    
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully','success')
    return redirect(url_for('login'))

@app.route('/user_home', methods=['GET', 'POST'])
def show_user_home():
    projects_data = Project.query.all()
    subtask = Subtask.query.all()
    project_query = 'SELECT * FROM project'
    epic_query = 'SELECT * FROM epic'
    story_query = 'SELECT * FROM story'
    subtask_query = 'SELECT * FROM subtask'
    users_query = 'SELECT * FROM users'
    project_df = pd.read_sql_query(sql=text(project_query), con=engine.connect())
    epic_df = pd.read_sql_query(sql=text(epic_query), con=engine.connect())
    story_df = pd.read_sql_query(sql=text(story_query), con=engine.connect())
    subtask_df = pd.read_sql_query(sql=text(subtask_query), con=engine.connect())
    users_df = pd.read_sql_query(sql=text(users_query), con=engine.connect())
    total_unique_projects = project_df["id"].nunique()
    total_unique_epics = epic_df["id"].nunique()
    total_unique_stories = story_df["id"].nunique()
    total_unique_subtasks = subtask_df["id"].nunique()
    role_counts = users_df['User_Role'].value_counts()
    trace = go.Pie(
    labels=role_counts.index,
    values=role_counts.values,
    hole=0.5,
    marker=dict(colors=['#F44336', '#FFEB3B', '#4CAF50', '#2196F3']),
)
    user_role = go.Figure(data=[trace])
    user_role_json = user_role.to_json()
    # convert the StartDate column to datetime
    subtask_df['StartDate'] = pd.to_datetime(subtask_df['StartDate'])

    # filter the data to only include the last 30 days
    last_30_days = dt.datetime.now() - dt.timedelta(days=30)
    subtask_count = subtask_df[subtask_df['StartDate'] >= last_30_days]

    # group the data by date and count the number of subtasks for each date
    subtasks_by_date = subtask_df.groupby(subtask_df['StartDate'].dt.date).count()['id']

    # create the line chart with data labels and lines
    trace = go.Scatter(
        x=subtasks_by_date.index,
        y=subtasks_by_date.values,
        mode='lines+markers+text',
        name='Subtasks',
        text=subtasks_by_date.values,
        textposition='top center',
        textfont=dict(size=10, color='black')
    )
    layout = go.Layout(
        xaxis=dict(title='Date'),
        yaxis=dict(title='Subtasks'),
        plot_bgcolor='white'
    )
    subtask_fig = go.Figure(data=[trace], layout=layout)
    subtask_fig_json = subtask_fig.to_json()
    user = None
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
        if user.User_Role == 'Member':
            assigned_subtasks_inprogress = Subtask.query.filter_by(AssignedTo=user.Email).filter_by(Status='InProgress').all()
            assigned_subtasks_complete = Subtask.query.filter_by(AssignedTo=user.Email).filter_by(Status='Complete').all()
            return render_template('member_home.html', 
                                   projects=projects_data, 
                                   user=user, subtask=subtask,
                                   assigned_subtasks_inprogress=assigned_subtasks_inprogress,
                                   assigned_subtasks_complete=assigned_subtasks_complete)

    return render_template('dashboard.html', projects=projects_data, total_unique_projects = total_unique_projects, total_unique_epics = total_unique_epics, total_unique_stories = total_unique_stories, total_unique_subtasks = total_unique_subtasks, user_role_json=user_role_json, subtask_fig_json=subtask_fig_json)

#PROJECTS PAGE:
@app.route('/projects')
def show_projects():
    projects_data = Project.query.all()
    return  render_template('home_project.html', projects= projects_data)

#USER CONTROL PAGE FOR ADMIN
@app.route('/user_control')
def show_users():
    users_data = Users.query.all()
    return  render_template('user_role_control.html', users= users_data)

@app.route('/update_user_role/<int:user_id>/<new_role>')
def update_user_role(user_id, new_role):
    user = Users.query.get(user_id)
    user.User_Role = new_role
    db.session.commit()
    return 'User role updated successfully'

#USER PROFILE FOR ALL USERS
@app.route('/user_profile')
def show_user_profile():
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
    return  render_template('user_profile.html', user= user)

#UPDATE PASSWORD
@app.route('/update_password', methods=['POST'])
def update_password():
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if the old password entered by the user is correct
        if not bcrypt.checkpw(old_password.encode('utf-8'), user.Password.encode('utf-8')):
            flash('Invalid Old Password', 'danger')
            return redirect(url_for('show_user_profile'))

        # Check if the new password and confirm password match
        if new_password != confirm_password:
            flash('New Password and Confirm Password do not match', 'danger')
            return redirect(url_for('show_user_profile'))

        # Hash the new password and update the user's password in the database
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user.Password = hashed_password
        db.session.commit()

        flash('Password Updated Successfully', 'success')
        return redirect(url_for('show_user_profile'))
    else:
        return redirect(url_for('login'))

# CREATE ROUTES FOR ALL HIERARCHIES
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        designation = request.form['designation']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        user_role = request.form['user_role']
        creation_date = dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30)

        if not email.endswith('@gwcteq.com'):
            flash('Only gwcteq.com emails are allowed to register', 'warning')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match', 'warning')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        user = Users(name=name, email=email, designation=designation, password=hashed_password,
                    user_role=user_role, creation_date=creation_date)
        db.session.add(user)
        db.session.commit()

        flash('You have been Successfully Registered! You can now login!!', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register_page.html')

@app.route('/add_project', methods=['POST', 'GET'])
def add_project():
    managers = Users.query.filter_by(User_Role='Manager').all()
    admins = Users.query.filter_by(User_Role='Admin').all()
    member=Users.query.filter_by(User_Role='Member').all()
    team_lead=Users.query.filter_by(User_Role='Team Lead').all()
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
    if request.method == 'POST':
        name = request.form['name']
        owner = request.form['owner']
        description = request.form['description']
        manager = request.form['manager']
        createdby=user.Email
        members = request.form.getlist('members')
        start_date = dt.datetime.strptime(request.form['start-date'], '%Y-%m-%d').date()
        end_date = dt.datetime.strptime(request.form['end-date'], '%Y-%m-%d').date()
        creationDate = dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30)

        project = Project(ProjectName=name, ProjectOwner=owner, ProjectDescription=description,
                          ProjectManager=manager, CreatedBy=createdby, Members=', '.join(members),
                          StartDate=start_date, EndDate=end_date, CreationDate=creationDate)
        db.session.add(project)
        db.session.commit()
        flash('Your Project has been Created Successfully!!', 'success')
        return redirect(url_for('show_projects'))
    else:
        return render_template('create_project.html', Managers=managers, Admins=admins, Members=member, Team_Lead=team_lead, user=user)

@app.route('/add_epic/<int:project_id>', methods=['GET', 'POST'])
def add_epic(project_id):
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
    if request.method == 'POST':
        epic_name = request.form['epic_name']
        created_by = user.Email.split('@')[0].lower()
        epic_description = request.form['epic_description']
        start_date = dt.datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = dt.datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        creationDate = dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30)
        
        # add the epic to the database with the project ID
        epic = Epic(EpicName=epic_name, CreatedBy=created_by, EpicDescription=epic_description,
                    StartDate=start_date, EndDate=end_date, CreationDate = creationDate, ProjectID=project_id)
        db.session.add(epic)
        db.session.commit()
        flash('Epic has been successfully added to the Project!!', 'success')
        return redirect(url_for('project_details', project_id=project_id))
    
    return render_template('create_epic.html', project_id=project_id, user=user)

@app.route('/add_story/<int:epic_id>', methods=['GET', 'POST'])
def add_story(epic_id):
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
    if request.method == 'POST':
        story_name = request.form['story_name']
        created_by = user.Name
        story_description = request.form['story_description']
        start_date = dt.datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = dt.datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        creationDate = dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30)
        
        # add the story to the database with the epic ID
        story = Story(StoryName=story_name, CreatedBy=created_by, StoryDescription=story_description,
                      StartDate=start_date, EndDate=end_date, CreationDate = creationDate, EpicID=epic_id)
        db.session.add(story)
        db.session.commit()
        
        epic = Epic.query.filter_by(id=epic_id).first()
        flash('UserStory has been added Successfully', 'success')
        return redirect(url_for('epic_details', epic_id=epic_id))
    
    return render_template('create_story.html', epic_id=epic_id, user=user)

@app.route('/add_subtask/<int:story_id>', methods=['GET', 'POST'])
def add_subtask(story_id):
    member=Users.query.filter_by(User_Role='Member').all()
    team_lead=Users.query.filter_by(User_Role='Team Lead').all()
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
    if request.method == 'POST':
        subtask_name = request.form['subtask_name']
        created_by = user.Email
        subtask_description = request.form['subtask_description']
        start_date = dt.datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = dt.datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        assignedto=request.form['assigned_to']
        creationDate = dt.datetime.utcnow() + dt.timedelta(hours=5, minutes=30)

        # add the subtask to the database with the story ID
        subtask = Subtask(SubtaskName=subtask_name, CreatedBy=created_by, SubtaskDescription=subtask_description,AssignedTo=assignedto,
                          StartDate=start_date, EndDate=end_date, CreationDate=creationDate, StoryID=story_id)
        db.session.add(subtask)
        db.session.commit()

        story = Story.query.filter_by(id=story_id).first()
        flash('SubTask has been added Successfully', 'success')
        return redirect(url_for('story_details', story_id=story_id))

    return render_template('create_subtask.html', story_id=story_id, user=user,Members=member,Team_Lead=team_lead)

#DETAILS ROUTE
@app.route('/project/<int:project_id>', methods=['POST', 'GET'])
def project_details(project_id):
    project = Project.query.get_or_404(project_id)
    epics_data = Epic.query.filter_by(ProjectID=project_id).all()
    return render_template('project_details.html', project=project, epics=epics_data, project_name=project.ProjectName)

@app.route('/epic/<int:epic_id>', methods=['GET'])
def epic_details(epic_id):
    epic = Epic.query.get_or_404(epic_id)
    stories_data = Story.query.filter_by(EpicID=epic_id).all()
    return render_template('epic_details.html', epic=epic, stories=stories_data)

@app.route('/story/<int:story_id>', methods=['GET'])
def story_details(story_id):
    story = Story.query.get_or_404(story_id)
    epic = Epic.query.get_or_404(story.EpicID)
    subtasks_data = Subtask.query.filter_by(StoryID=story_id).all()
    return render_template('story_details.html', epic=epic, story=story, subtasks=subtasks_data)

@app.route('/subtasks/<int:subtask_id>', methods=['GET', 'POST'])
def subtask_details(subtask_id):    
    subtask = Subtask.query.get_or_404(subtask_id)
    user = None
    if 'user_id' in session:
        user_id = session['user_id']
        user = Users.query.filter_by(id=user_id).first()
        if user.User_Role == 'Member' and user.Email != subtask.AssignedTo:
            abort(403)

    if request.method == 'POST':
        new_status = request.form['status']
        subtask.Status = new_status
        db.session.commit()
        if new_status == "Complete":
            flash("You have Marked the SubTask as Complete", 'success')
        elif new_status == "InProgress":
            flash("You have Marked the SubTask In Progress", 'warning')
        return redirect(url_for('show_user_home'))
        
    return render_template('subtask_details.html', subtask=subtask, user=user)

#DELETE ROUTES
@app.route('/project/<int:project_id>/delete_epic/<int:epic_id>', methods=['POST'])
def delete_epic(project_id, epic_id):
    epic = Epic.query.get_or_404(epic_id)

    # Retrieve all the stories and subtasks that are linked to the epic
    stories = Story.query.filter_by(EpicID=epic.id).all()
    subtasks = Subtask.query.filter(Subtask.StoryID.in_([s.id for s in stories])).all()

    # Delete the subtasks first, then the stories, and finally the epic
    for subtask in subtasks:
        db.session.delete(subtask)
    for story in stories:
        db.session.delete(story)
    db.session.delete(epic)
    db.session.commit()

    return redirect(url_for('project_details', project_id=project_id))

@app.route('/delete_story/<int:story_id>/',methods=['POST'])
def delete_story(story_id):
    # find the story to delete
    story = Story.query.filter_by(id=story_id).first()

    if story:
        # delete all of the subtasks associated with the story
        Subtask.query.filter_by(StoryID=story.id).delete()

        # delete the story from the database
        db.session.delete(story)
        db.session.commit()

        flash('UserStory deleted successfully','success')
    else:
        flash('UserStory not found', 'danger')

    return redirect(url_for('epic_details', epic_id=story.EpicID))

@app.route('/subtask/<int:subtask_id>/delete_subtask', methods=['POST'])
def delete_subtask(subtask_id):
    subtask = Subtask.query.get_or_404(subtask_id)
    db.session.delete(subtask)
    db.session.commit()
    flash('Subtask has been deleted.', 'success')
    return redirect(url_for('story_details', story_id=subtask.StoryID))

#UPDATE ROUTES
@app.route('/project/<int:project_id>/update_project', methods=['GET', 'POST'])
def update_project(project_id):
    project = Project.query.get_or_404(project_id)
    managers = Users.query.filter_by(User_Role='Manager').all()
    admins = Users.query.filter_by(User_Role='Admin').all()
    member=Users.query.filter_by(User_Role='Member').all()
    team_lead=Users.query.filter_by(User_Role='Team Lead').all()
    if request.method == 'POST':
        if 'ProjectName' in request.form:
            project.ProjectName = request.form['ProjectName']
        if 'ProjectOwner' in request.form:
            project.ProjectOwner = request.form['ProjectOwner']
        if 'ProjectDescription' in request.form:
            project.ProjectDescription = request.form['ProjectDescription']
        if 'ProjectManager' in request.form:
            project.ProjectManager = request.form['ProjectManager']
        if 'CreatedBy' in request.form:
            project.CreatedBy = request.form['CreatedBy']
        if 'Members' in request.form:
            project.Members = request.form['Members']
        if 'StartDate' in request.form:
            project.StartDate = dt.datetime.strptime(request.form['StartDate'], '%Y-%m-%d').date()
        if 'EndDate' in request.form:
            project.EndDate = dt.datetime.strptime(request.form['EndDate'], '%Y-%m-%d').date()
        db.session.commit()
        flash('Project details updated successfully!', 'success')
        return redirect(url_for('project_details', project_id=project.id))

    return render_template('update_project.html', project=project, Managers=managers, Admins=admins,Members=member,Team_Lead=team_lead)

@app.route('/epic/<int:epic_id>/update_epic', methods=['GET', 'POST'])
def update_epic(epic_id):
    epic = Epic.query.get_or_404(epic_id)
    if request.method == 'POST':
        epic.EpicName = request.form['EpicName']
        epic.EpicDescription = request.form['EpicDescription']
        epic.StartDate = dt.datetime.strptime(request.form['StartDate'], '%Y-%m-%d').date()
        epic.EndDate = dt.datetime.strptime(request.form['EndDate'], '%Y-%m-%d').date()
        db.session.commit()
        flash('Epic updated successfully!', 'success')
        return redirect(url_for('epic_details', epic_id=epic.id))
    return render_template('update_epic.html', epic=epic)

@app.route('/update_story/<int:story_id>', methods=['GET', 'POST'])
def update_story(story_id):
    story = Story.query.get(story_id)

    if request.method == 'POST':
        # Retrieve the updated values from the form and update the story object
        story.StoryName = request.form['StoryName']
        story.StoryDescription = request.form['StoryDescription']
        story.StartDate = dt.datetime.strptime(request.form['StartDate'], '%Y-%m-%d').date()
        story.EndDate = dt.datetime.strptime(request.form['EndDate'], '%Y-%m-%d').date()
        db.session.commit()

        # Redirect back to the story details page
        flash('UserStory has been Updated Sucessfully', 'success')
        return redirect(url_for('story_details', story_id=story.id))

    return render_template('update_story.html', story=story)

@app.route('/subtask/<int:subtask_id>/update_subtask', methods=['GET', 'POST'])
def update_subtask(subtask_id):
    subtask = Subtask.query.get(subtask_id)
    member=Users.query.filter_by(User_Role='Member').all()
    team_lead=Users.query.filter_by(User_Role='Team Lead').all()
    if request.method == 'POST':
        subtask.SubtaskName = request.form.get('SubtaskName')
        subtask.SubtaskDescription = request.form.get('SubtaskDescription')
        if 'assigned_to' in request.form:
            subtask.AssignedTo = request.form['assigned_to']
        subtask.StartDate = dt.datetime.strptime(request.form['StartDate'], '%Y-%m-%d').date()
        subtask.EndDate = dt.datetime.strptime(request.form['EndDate'], '%Y-%m-%d').date()
        db.session.commit()
        flash('The SubTask has been updated successfully', 'success')
        return redirect(url_for('story_details', story_id=subtask.StoryID ))

    return render_template('update_subtask.html', subtask=subtask, Members=member,Team_Lead=team_lead)

if __name__ == "__main__":
    app.run(debug=True)