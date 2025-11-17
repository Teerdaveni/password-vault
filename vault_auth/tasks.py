# from django.core.mail import send_mail
# from django.conf import settings
# from celery import shared_task


# @shared_task
# def send_otp_email(recipients, subject, message):
#     """Send OTP email to given recipients.

#     This task runs in the Celery worker process. It uses Django's
#     send_mail function which will be configured by Django settings.
#     """
#     try:
#         # Use DEFAULT_FROM_EMAIL to keep sender consistent with Django settings
#         from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', settings.EMAIL_HOST_USER)
#         send_mail(subject, message, from_email, recipients, fail_silently=False)
#         # Log success so worker output clearly shows delivery attempts
#         print(f"send_otp_email: sent to {recipients} (from {from_email})")
#         return {'status': 'sent', 'recipients': recipients}
#     except Exception as e:
#         # Log and re-raise so Celery records the failure.
#         print(f"send_otp_email failed: {e}")
#         raise


from django.core.mail import send_mail
from django.conf import settings
from celery import shared_task


@shared_task
def send_otp_email(recipients, subject, message):
    """Send OTP email to given recipients using Django mail system."""
    try:
        # Use DEFAULT_FROM_EMAIL for trusted verified email identity
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', settings.EMAIL_HOST_USER)

        send_mail(
            subject,
            message,
            from_email,
            recipients,
            fail_silently=False
        )

        print(f"send_otp_email: sent to {recipients} (from {from_email})")
        return {'status': 'sent', 'recipients': recipients}

    except Exception as e:
        print(f"send_otp_email failed: {e}")
        raise
