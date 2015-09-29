# -*- coding: UTF-8 -*-
import os
import sys

import requests
import tempfile
import random

from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext

from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password


import pprint
pp = pprint.PrettyPrinter()

def index(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        email = request.POST.get("email", "")
        filterResult=User.objects.filter(username=username)
        if len(filterResult)>0:
            return render_to_response("account/index.html",{"error": "用户名已存在!"}, context_instance=RequestContext(request))
        if username!="" and password!="" and email!="":
            user = User.objects.create_user(username,email,password)
            user.save()
            return render_to_response("success_simple.html", {"message":"注册成功!"}, context_instance=RequestContext(request))
        else:
            return render_to_response("error.html",{"error": "注册失败!"},context_instance=RequestContext(request))
    else:
        return render_to_response("account/index.html",{"error": ""}, context_instance=RequestContext(request))

@login_required
def profile(request):
    user_info = User.objects.filter(id=request.user.id)
    pp.pprint(user_info[0].__dict__)
    return render_to_response("account/profile.html",{"user_info": user_info[0]}, context_instance=RequestContext(request))

@login_required
def resetpasswd(request):
    if request.method == "POST":
	username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        email = request.POST.get("email", "")
        if password!="" and email!="":
           pp.pprint(make_password(password))
	   updateuser = get_user_model()._default_manager.get(pk=request.user.id)
           pp.pprint(make_password(password))
           updateuser.password=make_password(password)
           updateuser.email=email
	   updateuser.save()
           return render_to_response("success_simple.html", {"message":"用户资料修改成功!"}, context_instance=RequestContext(request))
        else:
           return render_to_response("error.html",{"error": "请重试,用户资料修改失败!"},context_instance=RequestContext(request))
    else:
        user_info = User.objects.filter(id=request.user.id)
        return render_to_response("account/resetpasswd.html",{"user_info": user_info[0]}, context_instance=RequestContext(request))
