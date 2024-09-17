from django.test import TestCase
from rest_framework import status
from django.test import Client
from rest_framework.test import APITestCase
from backend.models import *
import tempfile, csv, os
import json

class AppSync(APITestCase):
    def setUp(self):
        self.client = Client()
        self.app_root = '/api/v1/'

    def test_appSync(self):
        response = self.client.post(self.app_root + 'syncapp/', {'proname': 'EKM'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

class Asymmetric(APITestCase):
    def setUp(self):
        self.client = Client()
        self.app_root = '/api/v1/'
        self.client.post(self.app_root + 'syncapp/', {'proname': 'EKM'}, format='json')
        self.token = application.objects.create(application_name='EKM',application_api_token='57b31272c53017dffc827701754b16bc',application_created_date='2017-11-09 12:22:34.654281+00')
        self.test_user = User.objects.create_user(username='test',password='test123',email="antonylourduraj.amaloorpavaraj@nexttechnosolutions.co.in")
        self.secret=auth_key.objects.create(login_user_id=self.test_user.id,secret_code="asd45")


    def generate_file(self):
        try:
            myfile = open('test.csv', 'wb')
            wr = csv.writer(myfile)
            wr.writerow(('Paper ID', 'Paper Title', 'Authors'))
            wr.writerow(('1', 'Title1', 'Author1'))
            wr.writerow(('2', 'Title2', 'Author2'))
            wr.writerow(('3', 'Title3', 'Author3'))
        finally:
            myfile.close()

        return myfile

    def test_asymencrypt(self):
        response = self.client.post(self.app_root+'asymencrypt/', { "token":self.token.application_api_token, "data":"test" }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_asymdecrypt(self):
        response = self.client.post(self.app_root+'asymdecrypt/', { "token":self.token.application_api_token, "data":"Tdv/vM2xCX5YXIH9sOrIeFnZ74dXIqiqLN4WPmnM5ySDzykQHZ8Nt6sOGcNAYdH9hUxaM2RyR3F3yCPGbN31ETZ0k/Z5fxYkACvrTXTruZc6QXQDtcb/eCCxZz4unN8SiDai4N05XrBpOr35JE4sTg9Dn7o80USdgcGcNQIae7Q=" }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_symencrypt(self):
        post_data = {}
        myfile = self.generate_file()
        file_path = myfile.name
        f = open(file_path, "r")
        post_data['file'] = f
        post_data['token'] = self.token.application_api_token
        response = self.client.post(self.app_root+'symencrypt/', post_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_symdecrypt(self):
        response = self.client.get(self.app_root+'symdecrypt/'+self.token.application_api_token+'/test.csv')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login(self):
        print self.test_user.username
        response = self.client.post(self.app_root+'login/', {"username":"test","password":"test123"},format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_auth(self):
        response = self.client.post(self.app_root+'twofactor/', {"secret":self.secret.secret_code,"user":self.secret.login_user_id},format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_news(self):
        response = self.client.get(self.app_root + 'newsfeed/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_serverstatus(self):
        response = self.client.get(self.app_root + 'getserver/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_footer(self):
        response = self.client.get(self.app_root + 'footer/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_getapp(self):
        response = self.client.get(self.app_root + 'applications/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_getkeys(self):
        response = self.client.get(self.app_root + 'keys/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_getupdate(self):
        response = self.client.put(self.app_root + 'updateapp/',json.dumps({"app_id":str(self.token.id),"status":True}),'application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
