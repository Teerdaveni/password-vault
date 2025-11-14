"""Password Vault Django Project package.

This module initializes the Celery app for Django so tasks can be discovered
when a worker runs. Importing the app here lets `manage.py` and other Django
startup code import the Celery app automatically.
"""
try:
	from .celery import app as celery_app
	# Expose the Celery app as a module-level variable for discovery
	__all__ = ('celery_app',)
except Exception:
	# If Celery is not installed or the module cannot be imported during
	# startup (for example in environments without Celery), avoid failing
	# Django's import process. The OTP logic falls back to synchronous
	# send_mail when Celery is unavailable.
	celery_app = None
	__all__ = ()
