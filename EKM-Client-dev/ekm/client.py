import requests
import argparse
"""
    details: Make client request to EKM server
    author: Antony
    date: 15-11-2017
""" 
#EKM_BASE_URL='http://192.168.10.231:8000/api/v1/'
EKM_BASE_URL='http://10.0.1.6/api/v1/'

def generate_token():
    parser = argparse.ArgumentParser(description='Generate EKM token for the application')
    parser.add_argument('proname', metavar='ProjectName', type=str)
    pro_name = parser.parse_args().proname
    url = EKM_BASE_URL+'syncapp/'
    r = requests.get(url, params={"proname": pro_name})
    if r.status_code==200:
       return r.json()
    else:
       return 'Server error! Error in generating token.'

def ekm_process(token,intype,val,process):
    if intype=='string':
        if process=='encrypt':
            url = EKM_BASE_URL + 'asymencrypt/'
        elif process=='decrypt':
            url = EKM_BASE_URL + 'asymdecrypt/'
	#if isinstance(val,list):val=[str(i).strip() for i in val]	
	#if isinstance(val,list):val=[str(i) if not i=='' and not i==None else None for i in val]
	#if isinstance(val,dict):reval={i : j if not j=='' and not j==None else None for i,j in val.iteritems()}
	strdata = {'token': token, 'data': str(val)}
        r = requests.post(url, data=strdata)
        if r.status_code==200:
            return r.json()
        else:
            return 'server_error'
    elif intype=='file':
        if process=='encrypt':
            with open(val, 'rb') as f:
                url = EKM_BASE_URL + 'symencrypt/'
                token = {'token': token}
                r = requests.post(url, files={'file': f}, data=token)
            if r.status_code==200:
                return r.json()
            else:
                return 'server_error'
        elif process=='decrypt':
            infile=val.rsplit('/', 1)[-1]
            url = EKM_BASE_URL + 'symdecrypt/' + token + '/' + infile
            r=requests.get(url)
	    if r.status_code==200:
                with open(val, 'wb') as fd:
                    for chunk in r.iter_content():
                        fd.write(chunk)
            	return 'Decrypted file saved in the path given'
	    else:
                return 'server_error'
