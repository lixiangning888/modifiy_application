import os
import sys

import requests
import tempfile
import random

from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext

def index(request):
    return render_to_response("technique/index.html",context_instance=RequestContext(request))
