import time
import after_response
from backend.models import *
from django.core.mail import send_mail

def timer(func):
    '''
    :param func: function name
    :return: return the time taken for the each function
    :author Praveen.Josephmasilamani
    '''
    def checkTimer(*args,**kwargs):
        before = time.time()
        rv = func(*args,**kwargs)
        after = time.time()
        print("{} Taken: {}".format(func.__name__, after-before))
        return rv
    return checkTimer

"""
    details: Applications Activity
    author: Praveen Josephmasilamani
    date: 07-11-2017
"""
@after_response.enable
def AppActivity(**kwargs):
    try:
        getApp = application.objects.get(application_api_token=kwargs['token'])
        appActivity = activities(activities_app_id=getApp.id,activities_type=kwargs['type'],activities_data_name=kwargs['name'],activities_status=kwargs['status'])
        appActivity.save()
        return True
    except Exception as e:
        print(e)
        return False

@after_response.enable
def sendVerificationMail(**kwargs):
    try:
        auth_key.objects.update_or_create(login_user_id=kwargs['id'], defaults={"secret_code": kwargs['secret']})
        send_mail('EKM verification code', '', 'nexttechdev@gmail.com', recipient_list=[kwargs['useremail']], fail_silently=False,
                  html_message='Hi <b>' + kwargs['firstname'] + '</b>,<br/>&nbsp;&nbsp;&nbsp;&nbsp;Your EKM authentication code is <b>' + kwargs['secret'] + '</b>.<br/><br/>Regards,<br/>EKM Team')
        return True
    except Exception as e:
        print ("Email & update issue",e)
        return  False