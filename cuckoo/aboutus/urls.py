from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "aboutus.views.index"),
)
