from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemySchema
from flask_caching import Cache
from celery import Celery
from app import celery
from app.factory import create_app
from app.celery_utils import init_celery
from flask_restx import Api, Resource, fields






#Initialize App
app1 = Flask(__name__)
cache=Cache()


#Database
app1.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Bingo12345!@localhost/toDoList' #Connection Query
app1.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app1.config['SECRET_KEY'] = 'thisissecret'
app1.config['CACHE_TYPE'] = 'simple'




init_celery(celery, app1)

#Initialize Database
db = SQLAlchemy(app1)
ma = Marshmallow(app1)
cache.init_app(app1)

api=Api(app1)
name_space = api.namespace('', description='TODO Task List')





class Users(db.Model):
    userID = db.Column(db.Integer, primary_key=True)
    fullName = db.Column(db.String(25))
    email = db.Column(db.String(35), unique=True)
    password = db.Column(db.String(200))
    DOB = db.Column(db.Date)
    userlists = db.relationship("Lists", back_populates="users", uselist=False)

    def __init__(self, userID,fullName, email, password, DOB):
        self.userID=userID
        self.fullName=fullName
        self.email=email
        self.password=password
        self.DOB=DOB

class Lists(db.Model):
    listID = db.Column(db.Integer, db.ForeignKey("users.userID"), primary_key=True)
    users = db.relationship("Users", back_populates="userlists", uselist=False) #ONE TO ONE RELATIONSHIP BETWEEN USERS AND LISTS
    listtasks = db.relationship("Tasks") #ONE TO MANY RELATIONSHIP BETWEEN LISTS AND TASK
    noOfTasks = db.Column(db.Integer)
    creationDateTime = db.Column(db.DateTime)
    lastUpdateDateTime = db.Column(db.DateTime)

    def __init__(self, listID, noOfTasks, creationDateTime, lastUpdateDateTime):
        self.listID=listID
        self.noOfTasks=noOfTasks
        self.creationDateTime=creationDateTime
        self.lastUpdateDateTime=lastUpdateDateTime


class Tasks(db.Model):
    listID = db.Column(db.Integer, db.ForeignKey("lists.listID"))  
    taskID = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(25))
    description = db.Column(db.String(25))
    dueDateTime = db.Column(db.DateTime)
    completionDateTime = db.Column(db.DateTime)
    completeStatus = db.Column(db.Boolean)

    def __init__(self,taskID,listID, title, description, dueDateTime, completionDateTime, completeStatus):
        self.taskID=taskID
        self.listID=listID
        self.title=title
        self.description=description
        self.dueDateTime=dueDateTime
        self.completionDateTime=completionDateTime
        self.completeStatus=completeStatus

class userSchema(ma.Schema):
    class Meta:
        fields = ("userID","fullname","email","password","DOB")

class listSchema(ma.Schema):
    class Meta:
        fields = ("listID","noOfTasks", "creationDateTime","lastUpdateDateTime")

class taskSchema(ma.Schema):
    class Meta:
        fields = ("taskID","listID","title","description","dueDateTime","completionDateTime","completeStatus")


