# -*- coding: UTF-8 -*-
import os
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

import requests
import tempfile
import random

from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext

from forms import CaptchaForm
import forms

from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password

import smtplib
from email.mime.text import MIMEText

import pprint
pp = pprint.PrettyPrinter()

def index(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        email = request.POST.get("email", "")
        form = CaptchaForm(request.POST)
    
        filterResult=User.objects.filter(username=username)
        if len(filterResult)>0:
            return render_to_response("account/index.html",dict(form=form,error="用户名已存在!"), context_instance=RequestContext(request))
	if not form.is_valid():
            form = CaptchaForm()
	    return render_to_response("account/index.html",dict(form=form,error="验证码不正确!"), context_instance=RequestContext(request))        

        if username!="" and password!="" and email!="":
            user = User.objects.create_user(username,email,password)
            user.save()
            return render_to_response("success_simple.html", {"message":"注册成功!"}, context_instance=RequestContext(request))
        else:
            return render_to_response("error.html",{"error": "注册失败!"},context_instance=RequestContext(request))
    else:
        form = CaptchaForm()
        #pp.pprint(dict(form=form,error="用户名已存在!"))
        return render_to_response("account/index.html", dict(form=form), context_instance=RequestContext(request))

@login_required
def profile(request):
    user_info = User.objects.filter(id=request.user.id)
    #pp.pprint(user_info[0].__dict__)
    return render_to_response("account/profile.html",{"user_info": user_info[0]}, context_instance=RequestContext(request))

@login_required
def resetpasswd(request):
    if request.method == "POST":
	username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        email = request.POST.get("email", "")
        if password!="" and email!="":
           #pp.pprint(make_password(password))
	   updateuser = get_user_model()._default_manager.get(pk=request.user.id)
           #pp.pprint(make_password(password))
           updateuser.password=make_password(password)
           updateuser.email=email
	   updateuser.save()
           return render_to_response("success_simple.html", {"message":"用户资料修改成功!"}, context_instance=RequestContext(request))
        else:
           return render_to_response("error.html",{"error": "请重试,用户资料修改失败!"},context_instance=RequestContext(request))
    else:
        user_info = User.objects.filter(id=request.user.id)
        return render_to_response("account/resetpasswd.html",{"user_info": user_info[0]}, context_instance=RequestContext(request))

def verifyuser(request):
    if request.method == "POST":
       username = request.POST.get("username", "")
       #pp.pprint(username)
       filterResult=User.objects.filter(username=username)
       #user_object = dict(user_info=filterResult[0])
       #pp.pprint(user_object['user_info'].__dict__)
       if len(filterResult)>0:
          return render_to_response("account/sentemail.html", dict(user_info=filterResult[0]), context_instance=RequestContext(request))
       else:
          form = forms.VerifyUser()
          return render_to_response("account/verifyuser.html", dict(form=form, error="用户名错误!"), context_instance=RequestContext(request))
    else:
       form = forms.VerifyUser()
       return render_to_response("account/verifyuser.html", dict(form=form), context_instance=RequestContext(request))

def sentemail(request):
    if request.method == "POST":
       pp.pprint(request.POST)
       email = request.POST.get("email", "")
       filterResult=User.objects.filter(email=email)
       sender = 'SpiritShield@somewhere.com'
       ReceiverStr = '%s<%s>' % (filterResult[0].username, filterResult[0].email)
       receiver = [ReceiverStr]
       ResetLink = "http://10.120.30.231:1234/user/forgot_password/?username=%s&&email=%s&&referral=%s" % (filterResult[0].username, filterResult[0].email, filterResult[0].password)
       message = """From: %s
       To: %s
       Subject: 密码重置邮件

       密码重置链接: %s
       

       """ % (sender, ReceiverStr, ResetLink)

       try:
         # Port 1025 is testing server
         smtpObj = smtplib.SMTP('localhost', 1025)
         #smtpObj = smtplib.SMTP('localhost')
         smtpObj.sendmail(sender, receiver, message)         
         print "Successfully sent email"
       except smtplib.SMTPException:
         print "Error: unable to send email"

def forgotpassword(request):
    if request.method == "GET":
       username = request.GET.get("username", "")
       email = request.GET.get("email", "")
       passwd = request.GET.get("referral", "")
       filterResult=User.objects.filter(username=username, email=email, password=passwd)
       if len(filterResult)>0:
          return render_to_response(context_instance=RequestContext(request))
       else:
          pass
