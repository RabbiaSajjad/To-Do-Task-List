from main import db, app1, cache, celery, name_space
from main import Users, Lists, Tasks, userSchema, listSchema, taskSchema
from flask import request, jsonify, json, Response, make_response
import bcrypt,jwt, datetime, calendar
from functools import wraps
from fuzzywuzzy import fuzz
import logging
from celery.schedules import crontab
from app import factory
import app
from flask_restx import Api, Resource, fields




db.create_all()
logging.basicConfig(filename='test.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

user_schema = userSchema()
users_schema = userSchema(many=True)
list_schema = listSchema()
lists_schema = listSchema(many=True)
task_schema = taskSchema()
tasks_schema = taskSchema(many=True)



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message':'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(email=data['user']).first()
        except:
            return jsonify({'message':'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
        
    return decorated



#add a user
@name_space.route('/adduser')
class addUser(Resource):
    @token_required
    def post(self,current_user):
        if not current_user.fullName=='admin':
            return jsonify({'message':'Only admin can add a new user'})
        userid=request.json['userID']
        name=request.json['fullname']
        email=request.json['email']
        password=request.json['password']
        dob=request.json['DOB']

        hashed=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        logging.info('Creating User with user ID:{}'.format(userid))

        new_user=Users(userid,name,email,hashed,dob)
        db.session.add(new_user)
        db.session.commit()

        logging.info('User created with user ID:{}'.format(userid))


        return user_schema.jsonify(new_user)





#Register user (any one can register themselves)
@name_space.route('/registeruser')
class registerUser(Resource):
    def post(self):
        userid=request.json['userID']
        name=request.json['fullname']
        email=request.json['email']
        password=request.json['password']
        dob=request.json['DOB']

        hashed=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        logging.info('Creating User with user ID:{}'.format(userid))
        new_user=Users(userid,name,email,hashed,dob)
        db.session.add(new_user)
        db.session.commit()
        logging.info('User created with user ID:{}'.format(userid))

        return user_schema.jsonify(new_user)






#to get all users
@name_space.route('/users')
class getUsers(Resource):
    @token_required
    def get(self,current_user):
        if not current_user.fullName=='admin':
            return jsonify({'message':'Only admin can view all users'})
        
        logging.info('Admin viewing Users list')
        user_all=Users.query.all()
        output=users_schema.dump(user_all)
        logging.info('Users List viewed')
        return jsonify(output)






#to get all the lists
@name_space.route('/lists')
class getLists(Resource):
    @token_required
    def get(self,current_user):
        if not current_user.fullName=='admin':
            return jsonify({'message':'Only admin can view all user lists'})
        
        logging.info('Admin accessing all the lists')
        user_all=Users.query.all()
        output=users_schema.dump(user_all)
        list_all=Lists.query.all()
        output=lists_schema.dump(list_all)
    

        return jsonify(output)





#to add a list
@name_space.route('/addlist')
class addList(Resource):
    @token_required
    def post(self,current_user):
        listid=request.json['listID']
        noOfTasks=request.json['noOfTasks']
        creationDateTime=str(datetime.datetime.today())
        lastUpdateDateTime=str(datetime.datetime.today())

        if current_user.userID != listid: #if userID do not match
            return jsonify({'message':'Unauthorized User!'})

        logging.info('User with user ID:{} creating a list'.format(current_user.userID))
        new_list=Lists(listid,noOfTasks,creationDateTime,lastUpdateDateTime)
        db.session.add(new_list)
        db.session.commit()
        logging.info('User with user ID:{} created a list'.format(current_user.userID))


        return list_schema.jsonify(new_list)





@name_space.route('/addtask')
class addtask(Resource):
    @token_required
    def post(self,current_user):
        taskid=request.json['taskID']
        listid=request.json['listID']
        title=request.json['title'] 
        description=request.json['description']
        dueDateTime=request.json['dueDateTime']
        completionDateTime=None
        completeStatus=request.json['completeStatus']

        if current_user.userID != listid: #if userID do not match & the user is not admin
            return jsonify({'message':'Unauthorized User!'})

        logging.info('Creating task for user:{}'.format(current_user.userID))
        new_task=Tasks(taskid,listid,title,description,dueDateTime,completionDateTime,completeStatus)
        db.session.add(new_task)
        getUserList = Lists.query.filter_by(listID=listid).first()
        getUserList.lastUpdateDateTime=str(datetime.datetime.today())
        task_count=getUserList.query.filter_by(listID=listid).count()
        getUserList.noOfTasks=task_count+1
        db.session.commit()
        logging.info('Task:{} created for user:{}'.format(taskid,current_user.userID))

        return task_schema.jsonify(new_task)





@name_space.route('/userlist')
class userlist(Resource):
    @token_required
    def get(self,current_user):
        logging.info('Viewing tasks for user:{}'.format(current_user.userID))
        tasks=db.session.query(Tasks).filter_by(listID=current_user.userID).all()
        taskList=tasks_schema.dump(tasks)

        return jsonify(taskList)




@name_space.route('/deletetask/<int:task_id>')
class deletetask(Resource):
    def delete(self,current_user,task_id):
        if current_user.userID != userid: #if userID do not match & the user is not admin
            return jsonify({'message':'You can only delete your own tasks'})
        
        logging.info('Deleting task with task ID:{}'.format(taskid))
        task= Tasks.query.get(task_id)
        db.session.delete(task)
        db.session.commit()
        logging.info('Deleted task with task ID:{}'.format(taskid))
        return "Task Deleted"




@name_space.route('/updatetask/<int:task_id>')
class updatetask(Resource):
    def put(self,current_user,task_id):
        if current_user.userID != userid: #if userID do not match & the user is not admin
            return jsonify({'message':'You can only update your own tasks'})
        logging.info('Updating task with task ID:{}'.format(taskid))
        task= Tasks.query.get(task_id)
        task.title="Title updated"
        db.session.commit()
        logging.info('Updated task with task ID:{}'.format(taskid))
        return task_schema.jsonify(task)




@name_space.route('/markcomplete/<int:task_id>')
class mark_complete(Resource):
    @token_required
    def put(self,current_user,task_id):
        
        task= Tasks.query.get(task_id)

        if current_user.userID != task.listID: #if userID do not match & the user is not admin
            return jsonify({'message':'You can only update your own tasks'})

        logging.info('Marking task with task ID:{} as complete'.format(taskid))
        task.completeStatus=True
        task.completionDateTime=str(datetime.datetime.today())
        db.session.commit()
        logging.info('Marked task with task ID:{} as complete'.format(taskid))
        return task_schema.jsonify(task)





@name_space.route('/login')
class login(Resource):
    def get(self):
        auth = request.authorization

        if not auth or not auth.username or not auth.password:
            return make_response("Couldn't Verify",401, {"WWW.Authenticate":'Basic Realm="Login Required"'}) #message, status code, appropriate header

        user = Users.query.filter_by(email=auth.username).first()

        if not user:
            return make_response("Couldn't Verify username",401, {"WWW.Authenticate":'Basic Realm="Login Required"'})


        encoded=auth.password.encode('utf-8')
        en2=user.password.encode('utf-8')
        if bcrypt.checkpw(encoded,en2):
            token=jwt.encode({'user':auth.username, 'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8')})

        return make_response("Couldn't Verify password",401, {"www.authenticate":'Basic Realm="Login Required"'})





@name_space.route('/generateReport1')
class generateReport1(Resource):
    @token_required
    @cache.cached(timeout=900, key_prefix='report1')
    def get(self,current_user):

        totaltasks=Tasks.query.filter_by(listID=current_user.userID).count()
        completed=Tasks.query.filter_by(listID=current_user.userID,completeStatus=True).count()
        remaining=totaltasks-completed
        
        return jsonify({'Total Tasks':totaltasks, 'Completed Tasks':completed, 'Remaining Tasks':remaining})




@name_space.route('/generateReport2')
class generateReport2(Resource):
    @token_required
    @cache.cached(timeout=900, key_prefix='report2')
    def get(self,current_user):

        getlist=Lists.query.filter_by(listID=current_user.userID).first()
        completed=Tasks.query.filter_by(listID=current_user.userID,completeStatus=True).count()
        currentDate=datetime.datetime.today()
        creationDate = datetime.datetime.strptime(str(getlist.creationDateTime), '%Y-%m-%d %H:%M:%S')
        delta=currentDate.date() - creationDate.date()
        
        return jsonify({'Total Days':delta.days, 'Completed Tasks':completed, 'Average':completed/delta.days})



@name_space.route('/generateReport3')
class generateReport3(Resource):
    @token_required
    @cache.cached(timeout=900, key_prefix='report3')
    def get(self,current_user):

        count=0
        completed=Tasks.query.filter_by(listID=current_user.userID,completeStatus=False).all()
        currentDate=datetime.datetime.today()
        for t in completed:
            dueDate = datetime.datetime.strptime(str(t.dueDateTime), '%Y-%m-%d %H:%M:%S')
            delta=currentDate.date() - dueDate.date()
            if delta.days>0:
                count=count+1
        
        return jsonify({'Overdue Tasks Count':count})




@name_space.route('/generateReport4')
class generateReport4(Resource):
    @token_required
    @cache.cached(timeout=900, key_prefix='report4')
    def get(self,current_user):


        titles=[]
        completionDay=[]
        completed=Tasks.query.filter_by(listID=current_user.userID,completeStatus=True).all()
        for t in completed:
            completionDate = datetime.datetime.strptime(str(t.completionDateTime), '%Y-%m-%d %H:%M:%S')
            titles.append(t.title)
            completionDay.append(calendar.day_name[completionDate.weekday()])
            
        
        return jsonify({'Tasks':titles,'Completion-Days':completionDay})



@name_space.route('/similartasks')
class similartasks(Resource):
    @token_required
    def findSimilarTasks(self,current_user):

        userTasks=Tasks.query.filter_by(listID=current_user.userID).all()
        similar=[]
        for task1 in userTasks:
            for task2 in userTasks:
                if(task1.taskID!=task2.taskID):
                    ratio=fuzz.token_set_ratio(task1.description, task2.description)
                    if (ratio==100):
                        if task2 not in similar:
                            similar.append(task2)
        
        similar_list=tasks_schema.dump(similar)
        
        return jsonify(similar_list)



@name_space.route('/process/<name>')
class process(Resource):
    def get(self,name):
        text=reverse.delay(name)
        return 'Text Reversed'

@celery.task()
def reverse(text):
    return text[::-1]


if __name__ == "__main__":
    app1.run(debug=True)