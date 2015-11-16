# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns("",
    url(r"^$", "dashboard.views.index"),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^compare/", include("compare.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^statistics/", include("statistics.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", "analysis.views.file"),
    url(r"^filereport/(?P<task_id>[\w=]+)/(?P<category>\w+)/$", "analysis.views.filereport"),
    url(r"^full_memory/(?P<analysis_number>\w+)/$", "analysis.views.full_memory_dump_file"),
    url(r"^dashboard/", include("dashboard.urls")),
    url(r"^api/", include("api.urls")),
    url(r"^technique/", include("technique.urls")),
    url(r"^aboutus/", include("aboutus.urls")),
    url(r"login/$", "django.contrib.auth.views.login"),
    url(r"logout/$", "django.contrib.auth.views.logout"),
    url(r"^user/", include("account.urls")),
    url(r"^site_management/", admin.site.urls),
    url(r"^captcha/", include('captcha.urls')),
)
