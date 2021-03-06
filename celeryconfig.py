from celery.schedules import crontab
from datetime import timedelta


#CELERY_IMPORTS = ('app.tasks.test')
CELERY_TASK_RESULT_EXPIRES = 30
CELERY_TIMEZONE = 'UTC'

CELERY_ACCEPT_CONTENT = ['json', 'msgpack', 'yaml']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

CELERYBEAT_SCHEDULE = {
    'reverse': {
        'task': 'insertion.reverse',
        # Every minute
        'schedule': timedelta(seconds=1),
    }
}
