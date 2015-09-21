# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^(?P<left_id>[\w=]+)/$", "compare.views.left"),
    url(r"^(?P<left_id>[\w=]+)/(?P<right_id>[\w=]+)/$", "compare.views.both"),
    url(r"^(?P<left_id>[\w=]+)/(?P<right_hash>[\w=]+)/$", "compare.views.hash"),
)
