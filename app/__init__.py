from celery import Celery
from datetime import timedelta

class CeleryConfig:
    CELERY_IMPORTS = ('to-DoList.insertion')
    CELERY_TASK_RESULT_EXPIRES = 30
    CELERY_ACCEPT_CONTENT = ['json', 'msgpack', 'yaml']
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_TIMEZONE = 'Asia/Seoul'
    CELERY_ENABLE_UTC = False
# this is a place for scheduler with celery beat.
 
    CELERYBEAT_SCHEDULE = {
        "time_scheduler": {
            "task": "to-DoList.insertion.reverse", 
            "schedule": timedelta(seconds=3) #set schedule time ! 
        }
    }

def make_celery(app_name=__name__):
    redis_uri= 'redis://localhost:6379'
    return Celery(app_name, backend=redis_uri, broker=redis_uri)

celery=make_celery()