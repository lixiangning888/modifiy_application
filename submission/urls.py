# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "submission.views.index"),
    url(r"^submit_file/$", "submission.views.submit_file"),
    url(r"^submit_url/$", "submission.views.submit_url"),
    url(r"^ajax_submit_file/$", "submission.views.ajax_submit_file"),
    url(r"^ajax_submit_url/$", "submission.views.ajax_submit_url"),
    url(r"status/(?P<task_id>[\w=]+)/$", "submission.views.status"),
)
