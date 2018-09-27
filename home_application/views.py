# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云(BlueKing) available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""

from common.mymako import render_mako_context,render_json
from django.http import HttpResponse
from home_application.models import ExcRecord

import urllib
import requests
import json
import time
import base64

bk_app_code='ming-app1'
bk_app_secret='686ac73d-7a72-4d76-a722-bbc5e5621201'
head_data = {'Content-Type':'application/x-www-form-urlencoded'}
retrytimes=50
pausetime=1


def index(request):
	return render_mako_context(request, '/home_application/home.html')
    

def home(request):
    """
    首页
    """
    all_record = ExcRecord.objects.all()
    all_record = all_record[::-1]
    ctx = {
            'all_record': all_record
    }
    return render_mako_context(request, '/home_application/home.html',ctx)


def dev_guide(request):
    """
    开发指引
    """
    return render_mako_context(request, '/home_application/dev_guide.html')


def contactus(request):
    """
    联系我们
    """
    return render_mako_context(request, '/home_application/contact.html')

def exccmd(request):
	ip = request.POST.get('ip')
	cmd = request.POST.get('cmd')
	result = exc_cmd(ip,cmd)
	if result != 'cmd_exc_timeout':
                r = True
        else:
                r = False
        cmd = base64.decodestring(cmd)
	current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
	exc_record = ExcRecord(ip=ip,cmd=cmd,result=r,exctime=current_time)
	exc_record.save()
	return render_json({'result':r,'excresult':result})

def filedistrib(request):
    return render_mako_context(request,'/home_application/file_distribution.html')

def devicemanage(request):
    return render_mako_context(request,'/home_application/device_manage.html')
        

	
	
def gen_session():
    username='admin'
    password='123456Qw'
    rurl='http://paas.bk.com/login/?c_url=/' 
    try:
    ######------get csrf_token------######
        session = requests.session()
        res = session.get(rurl)
        setcookie = str(res.headers['Set-Cookie']).split(';')[0]
        csrfmiddlewaretoken = setcookie.split('=')[1]
        #print csrfmiddlewaretoken
        
    ######------init login_data------######
        post_data={'csrfmiddlewaretoken':csrfmiddlewaretoken,'username':username,'password':password}
        post_data=urllib.urlencode(post_data) 
        
    ######------post login_data & get bk_token------######
        r = session.post(rurl,data = post_data,headers=head_data,allow_redirects=False)
        bk_token=str(r.headers['Set-Cookie']).split('bk_token=')[1]
        bk_token=bk_token.split(';')[0]
        #print bk_token
        return [session,bk_token]
    except Exception,e:
        print 'gen_session error:'
        print e

def exc_cmd(ip,cmd):   
######------get_bk_agent_status------######
    new_session = gen_session()
    session = new_session[0]
    bk_token = new_session[1]
    try:
        purl='http://paas.bk.com/api/c/compapi/v2/job/fast_execute_script/'
        post_data=json.dumps(
            {
                "bk_app_code": bk_app_code,
                "bk_app_secret": bk_app_secret,
                "bk_token": bk_token,
                "bk_supplier_id": 0,
                "bk_biz_id": 2,
                "script_content": cmd,
                "script_timeout": 1000,
                "account": "root",
                "is_param_sensitive": 0,
                "script_type": 1,
                "ip_list": [
                    {
                        "bk_cloud_id": 0,
                        "ip": ip
                    }
                ]
            }
        )
        response = session.post(purl,data = post_data,headers=head_data)
        result = str(response.content)
        #print result
        job_instance_id = result.split('"job_instance_id": ')[1].split(',')[0]
        purl='http://paas.bk.com/api/c/compapi/v2/job/get_job_instance_log/'
        post_data=json.dumps(
            {
                "bk_app_code": bk_app_code,
                "bk_app_secret": bk_app_secret,
                "bk_token": bk_token,
                "bk_biz_id": 2,
                "job_instance_id": job_instance_id
            }
        )
        isfinished = 0
        for i in range(0,retrytimes):
            response = session.post(purl,data = post_data,headers=head_data)
            result = str(response.content)
            #print result
            status = result.split('"status": ')[1].split(',')[0]
            if status == '3':
                isfinished = 1
                result = result.split('"log_content": "')[1].split('", "exit_code"')[0].split(r'\n')
		return result
                break
            else:
                time.sleep(pausetime)
        if isfinished == 0:
            return 'cmd_exc_timeout'
    
    except Exception,e:
        print 'exc_cmd error:'
        print e
    
    session.close()
        
def push_file(src_file,target_path,ip):
    new_session = gen_session()
    session = new_session[0]
    bk_token = new_session[1]
    try:
        purl='http://paas.bk.com/api/c/compapi/v2/job/fast_push_file/'
        post_data=json.dumps(
            {
                "bk_app_code": bk_app_code,
                "bk_app_secret": bk_app_secret,
                "bk_token": bk_token,
                "bk_biz_id": 2,
                "file_target_path": target_path,
                "file_source": [
                    {
                        "files": [
                            src_file
                        ],
                        "account": "root",
                        "ip_list": [
                            {
                                "bk_cloud_id": 0,
                                "ip": ip
                            }
                        ]
                    }
                ],
                "ip_list": [
                    {
                        "bk_cloud_id": 0,
                        "ip": ip
                    }
                ],
                "account": "root",
            }
        )
        response = session.post(purl,data = post_data,headers=head_data)
        result = str(response.content)
        return result
        
    except Exception,e:
        print 'push_file error:'
        print e    
        
    session.close()	

