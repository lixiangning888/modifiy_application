from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^register/$", "account.views.index"),
    url(r"^profile/$", "account.views.profile"),
    url(r"^resetpasswd/$", "account.views.resetpasswd"),
    url(r"^verify_user/$", "account.views.verifyuser"),
    url(r"^sentemail/$", "account.views.sentemail"),
)
