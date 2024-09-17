import os
import logging
import mimetypes
import binascii
from rest_framework.decorators import api_view
from rest_framework.response import Response
from EKM.utils import timer, AppActivity
from rest_framework import status
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from backend.SymmetricEncryption import SymmetricEncryption as sym
from backend.AsymmetricEncryption import AsymmetricEncryption as asym
from backend.AsymmetricEncryption import generate_keys
from backend.serializers import KeySerializer
from wsgiref.util import FileWrapper
from backend.models import *
from backend.serializers import *
from django.http import HttpResponse
from django.utils.encoding import smart_str
from Crypto.PublicKey import RSA
import datetime
import hashlib
import struct
from random import choice
from django.utils import timezone
import redis
import pickle
import requests
import backend.MediaServer as MS
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from jenkinsapi.jenkins import Jenkins
from xmljson import parker, Parker
from xml.etree.ElementTree import fromstring
from json import dumps, loads
import json
import ast
from EKM.utils import sendVerificationMail


SECURE_PATH = '/home/nextaps/EncryptedStorage/media/'
SECURE_TEMP_PATH = '/home/nextaps/EncryptedStorage/temp/'

"""
    Get the constant variables
"""
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

# instantiate
config = ConfigParser()
# parse existing file
try:
    config.read('constant.ini')
except Exception as e:
    logging.error({'Gather Constant Variable Error': e})

"""
    Logging basic Configuration
"""
logging.basicConfig(filename=settings.BASE_DIR+'/log/ekm.log',level=logging.DEBUG, format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s: ', datefmt='%m/%d/%Y %I:%M:%S %p', filemode='a')

"""
Establish connection with redis server
"""
redis_connect = redis.StrictRedis(host='localhost', port=6379, db=0)

"""
    details: Some security reasons add invalid function
"""
@api_view(['GET'])
@timer
def Invalid(request):
    content = {'Error': 'Enter the valid URL'}
    return Response(content, status=status.HTTP_404_NOT_FOUND)

"""
    details: Data(String) Asymmetric Encryption and Decryption
    algorithm: AES 256
    author: Praveen Josephmasilamani
    date: 25-10-2017
"""
@api_view(['POST'])
@timer
def AsymEncrypt(request):
    '''
        :param request: Application Token and data to encrypt
        :return: Encrypted string
    '''
    try:
        app_token = request.data.get('token')
        get_string = request.data.get('data')
        if str(get_string).find('}') != -1:
            encrypt_string = ast.literal_eval(str(get_string))
        else:
            encrypt_string = str(get_string)
        if not app_token:
            logging.error({'Token Not found Error'})
            return Response("Token Not found Error", status=status.HTTP_204_NO_CONTENT)
        elif not encrypt_string:
            logging.error({'Data Not found Error'})
            return Response("Data Not found Error", status=status.HTTP_204_NO_CONTENT)
        else:
            try:
                getKey = setRedisvalues(app_token)
                if not getKey=='banned_token':
                    keyPub = RSA.importKey(pickle.loads(redis_connect.hget(app_token, 'public')))
                else:
                    return Response('Banned Application',status=status.HTTP_204_NO_CONTENT)
                try:
                    if type(encrypt_string) is dict:
                        encrypted_msg = []
                        encrypted_str = {}
                        for k,i in encrypt_string.iteritems():
                            if i and i != 'None':
                                encrypted_str[k] = asym(i, keyPub, "none").encrypt_message()
                            elif i == '' or i == 'None':
                                encrypted_str[k] = 'None'
                            else:
                                encrypted_str[k] = 'None'
                        encrypted_msg.append(encrypted_str)
                        AppActivity.after_response(token=app_token, type="Encrypt", name="String", status="1")
                        return Response(encrypted_msg, status=status.HTTP_200_OK)
                    else:
                        encrypted_msg = asym(encrypt_string, keyPub, "none").encrypt_message()
                        AppActivity.after_response(token=app_token, type="Encrypt", name="String", status="1")
                        return Response(encrypted_msg, status=status.HTTP_200_OK)
                except Exception as e:
                    logging.error({'Encryption Error':e})
                    AppActivity.after_response(token=app_token, type="Encrypt", name="String", status="0")
                    return Response('Encryption Error',status=status.HTTP_204_NO_CONTENT)
            except Exception as e:
                logging.error({'Token Mismatch Error': e})
                return Response("Token Mismatch Error, Please check token",status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response("Request Error, Please check the parameters", status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
@timer
def AsymDecrypt(request):
    '''
        :param request: Application Token and Encrypted String
        :return: Decrypted String
    '''
    try:
	print"fffffffff"
        encrypt_string = request.data.get('data')
        app_token = request.data.get('token')
	print"VVVVVVVV",encrypt_string,app_token

        if not app_token:
            logging.error({'Token Not found Error'})
            return Response("Token Not found Error", status=status.HTTP_204_NO_CONTENT)
        elif not encrypt_string:
            logging.error({'Data Not found Error'})
            return Response("Data Not found Error", status=status.HTTP_204_NO_CONTENT)
        else:
            try:
                getKey = setRedisvalues(app_token)
	        print"GETTTTTTTTT",getKey
                if not getKey == 'banned_token':
                    keyPub = RSA.importKey(pickle.loads(redis_connect.hget(app_token, 'private')))
                else:
                    return Response('Banned Application',status=status.HTTP_204_NO_CONTENT)
                try:
                    if encrypt_string[0] == '[' and encrypt_string[::-1][0] == ']':
                    # if type(encrypt_string) is list:
                        remove_f_bracket = encrypt_string[1:]
                        remove_l_bracket = remove_f_bracket[:-1]
                        split_word = remove_l_bracket.replace(' ','').replace('\'','').split(',')
                        #decrypted_msg = [asym(i, 'none', keyPub).decrypt_message() for i in split_word]
                        decrypted_msg = []
                        for i in split_word:
                            if i and i != 'None':
                                decrypted_msg.append(asym(i, 'none', keyPub).decrypt_message())
                            elif i == '' or i == 'None':
                                decrypted_msg.append('None')
                            else:
                                decrypted_msg.append('None')
                        AppActivity.after_response(token=app_token, type="Decrypt", name="String", status="1")
                        return Response(decrypted_msg, status=status.HTTP_200_OK)
                    else:
		        print"ERRRRRRRR",e
                        decrypted_msg = asym(encrypt_string, 'none', keyPub).decrypt_message()
                        AppActivity.after_response(token=app_token, type="Decrypt", name="String", status="1")
                        return Response(decrypted_msg, status=status.HTTP_200_OK)
                except Exception as e:
		    print"ERRRRRRRR",e
                    logging.error({'Decryption Error': e})
                    AppActivity.after_response(token=app_token, type="Decrypt", name="String", status="0")
                    return Response('Decryption Error, Please check the data',status=status.HTTP_204_NO_CONTENT)
            except Exception as e:
                logging.error({'Token Mismatch Error': e})
                return Response("Token Mismatch Error, Please check token", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
	print"EEEEEEEEEEE",e
        logging.error({'Request Error': e})
        return Response("Request Error, Please check the parameters", status=status.HTTP_204_NO_CONTENT)

"""
    details: Data(File) symmetric Encryption and Decryption
    algorithm: Blowfish
    author: Praveen Josephmasilamani
    date: 25-10-2017
"""
@api_view(['POST'])
@timer
def SymEncrypt(request):
    '''
        :param request: file ana app token
        :return: Success and failed, Stored the encrypted file in secured storage
    '''
    try:
        file = request.data.get('file')
        app_token = request.data.get('token')
        if not app_token:
            logging.error({'Token Not found Error'})
            return Response("Token Not found Error", status=status.HTTP_204_NO_CONTENT)
        elif not file:
            logging.error({'Data Not found Error'})
            return Response("Data Not found Error", status=status.HTTP_204_NO_CONTENT)
        else:
            try:
                upload_dir = default_storage.save(file.name, ContentFile(file.read()))
                tmp_file = os.path.join(settings.MEDIA_ROOT, upload_dir)
                getKey = setRedisvalues(app_token)
                if not getKey == 'banned_token':
                    symkey = redis_connect.hget(app_token, 'symkey')
                else:
                    return Response('Banned Application',status=status.HTTP_204_NO_CONTENT)
                # encrypt = sym(str(symkey),str(tmp_file),config.get('ekm_backend','SECURE_PATH')).encrypt()
                encrypt = sym(str(symkey), str(tmp_file), SECURE_PATH).encrypt()
                if encrypt is True:
                    os.remove(tmp_file)
                    #return Response({'filename': file.name, 'Encrypted': 'Success'}, status=status.HTTP_200_OK)
                    try:
                        MS.Syncfiles()
                        os.remove(tmp_file+'.enc')
                        AppActivity.after_response(token=app_token, type="Encrypt", name="File", status="1")
                        return Response({'filename': file.name, 'Encrypted': 'Success'}, status=status.HTTP_200_OK)
                    except Exception as e:
                        logging.error({'File Sync Error'})
                        AppActivity.after_response(token=app_token, type="Encrypt", name="File", status="0")
                        return Response("File Sync Error", status=status.HTTP_204_NO_CONTENT)
                else:
                    logging.error({'Encrypt Error'})
                    return Response("Encrypt Error",status=status.HTTP_204_NO_CONTENT)
            except Exception as e:
                logging.error({'Token Mismatch Error': e})
                return Response('Token Mismatch Error',status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response("Request Error, Please check the parameters", status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@timer
def SymDecrypt(request, file=None, token=None):
    '''
    :param request: Decrypted File & Application Token
    :return: Decrypt the file and download the file
    '''
    try:
        getKey = setRedisvalues(token)
        if not getKey == 'banned_token':
            symkey = redis_connect.hget(token, 'symkey')
        else:
            return Response('Banned Application',status=status.HTTP_204_NO_CONTENT)
        try:
            try:
                MS.Getfile(file)
            except Exception as e:
                logging.error({'Media Server Error': e})
                return Response('Media Server Error', status=status.HTTP_204_NO_CONTENT)
            # derypt = sym(symkey, config.get('ekm_backend','SECURE_PATH')+file+'.enc', config.get('ekm_backend','SECURE_TEMP_PATH')).decrypt()
            derypt = sym(symkey, SECURE_PATH + file + '.enc', SECURE_TEMP_PATH).decrypt()
            if derypt is True:
                try:
                    file_path = str(os.path.join(config.get('ekm_backend','SECURE_TEMP_PATH'), file))
                    enc_file_path = str(os.path.join(config.get('ekm_backend','SECURE_PATH'), file)+'.enc')
                    file_wrapper = FileWrapper(open(file_path, 'rb'))
                    file_mimetype = mimetypes.guess_type(file_path)
                    response = HttpResponse(file_wrapper, content_type=file_mimetype)
                    response['X-Sendfile'] = file_path
                    response['Content-Length'] = os.stat(file_path).st_size
                    response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(file)
                    os.remove(file_path)
                    os.remove(enc_file_path)
                    AppActivity.after_response(token=token, type="Decrypt", name="File", status="1")
                    return response
                except Exception as e:
                    logging.error({'Decryption Error': e})
                    AppActivity.after_response(token=token, type="Decrypt", name="File", status="0")
                    return Response('Decryption Error',status=status.HTTP_204_NO_CONTENT)
            else:
                return Response('Decryption Failed! Please check your file name.',status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logging.error({'No File Found Error': e})
            return Response('No File Found Error', status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response("Request Error, Please check the parameters", status=status.HTTP_204_NO_CONTENT)

"""
    Generate token for applications
"""
@api_view(['GET'])
@timer
def syncapp(request):
    try:
        proname = request.GET.get('proname')
        app=application.objects.filter(application_name=proname).exists()
        if app:
            apptoken=application.objects.filter(application_name=proname).values('application_api_token')
            for tk in apptoken:
                token=tk['application_api_token']
            response='Application already exists. Please use the below token\n'+token
        else:
            token = binascii.hexlify(os.urandom(16)).decode('ascii')
            with open('/usr/share/dict/words') as f:
                words = [word.strip() for word in f]
                ranword = (' '.join(choice(words) for i in range(4))+token).replace(" ","")
            iouPad1 = b'\x4B\x58\x21\x81\x56\x7B\x0D\xF3\x21\x43\x9B\x7E\xAC\x1D\xE6\x8A'
            iouPad2 = b'\x80' + 39 * b'\0'
            md5input = iouPad1 + iouPad2 + struct.pack('!i', 14536) + iouPad1 + bytes(ranword)
            key = hashlib.md5(md5input).hexdigest()[:16]
            private,public=generate_keys()
            addapp = application(application_name=proname, application_api_token=token,
                                 application_created_date=datetime.datetime.now())
            addapp.save()
            keypair=keys(key_app_id=addapp,key_secret=key,key_public=public.exportKey(),key_private=private.exportKey())
            keypair.save()
            response='Application has been registered and your token is\n'+token
        return Response(response)
    except Exception as e:
        logging.error({'Error in generating token': e})
        return Response('Error in generating token',status=status.HTTP_204_NO_CONTENT)

"""
    Set Redis cache values
"""
def setRedisvalues(app_token):
    print"GGGGGGGGG",redis_connect.hlen(app_token)
    if redis_connect.hlen(app_token)==3:
	print"OOOOO"
        return True
    else:
	print"JJJJJJ"
        getApp = application.objects.get(application_api_token=app_token)
        isactive=getApp.is_active
        print"fddddddddd",getApp,isactive
        if isactive:
            getKey = keys.objects.get(key_app_id=getApp.id)
            keys_dict = {"public": pickle.dumps(getKey.key_public),
                         "private": pickle.dumps(getKey.key_private), "symkey": getKey.key_secret}
            redis_connect.hdel(app_token,*keys_dict.keys())
            setredis = redis_connect.hmset(app_token, keys_dict)
            return setredis
        else:
            return 'banned_token'

"""
    details: Get the Applications
    author: Praveen Josephmasilamani
    date: 25-10-2017
"""
@api_view(['GET'])
@timer
def getApp(request):
    try:
        app_data = application.objects.all()
        try:
            data_serial = AppSerializer(app_data,many=True).data
            return Response(data_serial, status=status.HTTP_200_OK)
        except Exception as e:
            logging.error({'Serailize Error': e})
            return Response("Serialize Error", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response("There is No data", status=status.HTTP_204_NO_CONTENT)


"""
    details: Get the Keys
    author: Praveen Josephmasilamani
    date: 02-11-2017
"""
@api_view(['GET'])
@timer
def getKey(request,app_id):
    try:
        key_data = keys.objects.get(key_app_id=app_id)
        try:
            if key_data:
                # data_serial = KeySerializer(key_data).data
                return Response(1,status=status.HTTP_200_OK)
            else:
                return Response("There is No data", status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logging.error({'Serailize Error': e})
            return Response("Serialize Error", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'There is No data': e})
        return Response("There is No data", status= status.HTTP_204_NO_CONTENT)

"""
    details: Get the Keys Count
    author: Praveen Josephmasilamani
    date: 02-11-2017
"""
@api_view(['GET'])
@timer
def getKeys(request):
    try:
        key_data = keys.objects.count()
        try:
            return Response(key_data,status=status.HTTP_200_OK)
        except Exception as e:
            logging.error({'Serailize Error': e})
            return Response("Serialize Error", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response("There is No data", status=status.HTTP_204_NO_CONTENT)

"""
    details: Get the all Encryption
    author: Praveen Josephmasilamani
    date: 02-11-2017
"""
@api_view(['GET'])
@timer
def getEncryptions(request):
    try:
        app_data = activities.objects.filter(activities_type="Encrypt")
        try:
            data_serial = ActivitySerializer(app_data, many=True).data
            return Response(data_serial,status=status.HTTP_200_OK)
        except Exception as e:
            logging.error({'Serailize Error': e})
            return Response("Serialize Error", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response("There is No data", status=status.HTTP_204_NO_CONTENT)

"""
    details: Get the all Encryption Count
    author: Praveen Josephmasilamani
    date: 02-11-2017
"""
@api_view(['GET'])
@timer
def getEncryptionsCount(request,app_id):
    try:
        app_data = activities.objects.filter(activities_app_id=app_id,activities_type="Encrypt").count()
        try:
            if app_data:
                return Response(app_data, status=status.HTTP_200_OK)
            else:
                return Response("There is No data", status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logging.error({'Serailize Error': e})
            return Response("Serialize Error", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'There is No data': e})
        return Response("There is No data", status=status.HTTP_204_NO_CONTENT)

"""
    details: Get the all Decryption Count
    author: Praveen Josephmasilamani
    date: 02-11-2017
"""
@api_view(['GET'])
@timer
def getDecryptionsCount(request,app_id):
    try:
        app_data = activities.objects.filter(activities_app_id=app_id,activities_type="Decrypt").count()
        try:
            if app_data:
                return Response(app_data, status=status.HTTP_200_OK)
            else:
                return Response("There is No data", status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logging.error({'Serailize Error': e})
            return Response("Serialize Error", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'There is No data': e})
        return Response("There is No data", status=status.HTTP_204_NO_CONTENT)

"""
    details: Get the all Decryption
    author: Praveen Josephmasilamani
    date: 02-11-2017
"""
@api_view(['GET'])
@timer
def getDecryptions(request):
    try:
        app_data = activities.objects.filter(activities_type="Decrypt")
        try:
            data_serial = ActivitySerializer(app_data, many=True).data
            return Response(data_serial,status=status.HTTP_200_OK)
        except Exception as e:
            logging.error({'Serailize Error': e})
            return Response("Serialize Error", status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response("There is No data", status=status.HTTP_204_NO_CONTENT)

"""
    details: Login functionality
    author: Antony
    date: 06-11-2017
"""
@api_view(['POST'])
@timer
def login_auth(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            usermail=token.user.email
            username=token.user.username
            userid=token.user.id
            tokenkey=token.key
            if usermail:
                secret=binascii.hexlify(os.urandom(4)).decode('ascii')
                try:
                    sendVerificationMail.after_response(id=userid, firstname=token.user.first_name, useremail=usermail, secret=secret)
                    return Response(json.dumps(
                        {'token':tokenkey, 'userid': userid, 'user': username,'email':usermail,'secret':secret,
                         'status': 'logged_in'}), status=status.HTTP_200_OK)
                except Exception as e:
                    logging.error({'Mail Send Error': e})
                    return Response(json.dumps({'status':'mail_send_error'}))
            else:
                return Response(json.dumps({'status': 'mail_error'}))
        else:
            return Response(json.dumps({'status':'login_failure'}))
    except Exception as e:
        logging.error({'Request Error': e})
        return Response('Request Error '+str(e))

"""
    details: Auth code
    author: Antony
    date: 07-11-2017
"""
@api_view(['POST'])
@timer
def verifysecret(request):
    try:
        sec_code=request.data.get('secret')
        user = request.data.get('user')
        verify=auth_key.objects.filter(secret_code=sec_code,login_user=user).exists()
        if verify:
            return Response('valid',status=status.HTTP_200_OK)
        else:
            return Response('invalid')
    except Exception as e:
        logging.error({'Request Error': e})
        return Response('Request Error '+str(e),status=status.HTTP_204_NO_CONTENT)

"""
    details: News Feed
    author: Praveen Josephmasilamani
    date: 07-11-2017
"""
@api_view(['GET'])
@timer
def getNewsfeed(request):
    try:
        # data = requests.get("http://www.techradar.com/rss")
        data = requests.get('https://rss.packetstormsecurity.com/news/tags/cryptography/')
        return Response(loads(dumps(parker.data(fromstring(data.content)))),status=status.HTTP_200_OK)
    except Exception as e:
        logging.error({'Issue': e})
        return Response('Problem', status=status.HTTP_204_NO_CONTENT)

"""
    details: Active / Deactive Applications
    author: Praveen Josephmasilamani
    date: 08-11-2017
"""
@api_view(['PUT'])
@timer
def ApplicationStatus(request):
    try:
        appid = request.data.get('app_id')
        app_status = request.data.get('status')
        if app_status == True:
            try:
                data = application.objects.filter(id=appid).update(is_active=False)
                if data:
                    return Response('Updated', status=status.HTTP_200_OK)
                else:
                    return Response('Failed', status=status.HTTP_204_NO_CONTENT)
            except Exception as e:
                logging.error({'Issue': e})
                return Response('Problem', status=status.HTTP_204_NO_CONTENT)
        elif app_status == False:
            try:
                data = application.objects.filter(id=appid).update(is_active=True)
                if data:
                    return Response('Updated', status=status.HTTP_200_OK)
                else:
                    return Response('Failed', status=status.HTTP_204_NO_CONTENT)
            except Exception as e:
                logging.error({'Issue': e})
                return Response('Problem', status=status.HTTP_204_NO_CONTENT)
        else:
            logging.error('Status Mismatch')
            return Response('Status Mismatch', status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logging.error({'Request Error': e})
        return Response('Request Error', status=status.HTTP_204_NO_CONTENT)

"""
    details: HA Proxy Server Status
    author: Praveen Josephmasilamani
    date: 08-11-2017
"""

@api_view(['GET'])
@timer
def getServerStatus(request):
    data = requests.get("http://ekm-api.nexttechnosolutions.com/haproxy?stats;csv")
    data_str = data.content
    data_filter = data_str.split("srv_abrt",1)[1]
    data_final = data_filter.split("webfarm,")[1:5]
    final_data = [dict({'name':d.split(',')[:1][0],'status':d.split(',')[16:17][0],'bytes_in':d.split(',')[7:8][0],'bytes_out':d.split(',')[8:9][0],'sessions':d.split(',')[6:7][0]}) for d in data_final]
    return Response(final_data)

"""
    details: Footer info
    author: Antony
    date: 08-11-2017
"""
@api_view(['GET'])
@timer
def footerinfo(request):
    try:
        # Getting Jenkins Build Number
        server = Jenkins("http://fusion.nexttechnosolutions.com:8080", username='secureon', password='secure@123')
        # running = job_instance.is_queued_or_running()
        pro_instance=[server.get_job('SecureON-EKM-WebApp-Prod'),server.get_job('SecureON-EKM-WebApp-Test')]
        prolist=[[str(build.get_last_build()).partition('#')[-1],build.get_last_build().get_timestamp().strftime('%d %b %Y')] for build in pro_instance]
        return Response(prolist,status=status.HTTP_200_OK)
    except Exception as e:
        logging.error({'Jenkins Error': e})
        return Response('Jenkins Error',status=status.HTTP_204_NO_CONTENT)
