"""Celery application for the password_vault Django project.

This file creates a Celery instance and configures it from Django settings.
Worker processes should be started with this app (e.g. `celery -A password_vault worker -l info`).
"""
import os
from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'password_vault.settings')

app = Celery('password_vault')

# Using a string here means the worker doesn't have to serialize the
# configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
