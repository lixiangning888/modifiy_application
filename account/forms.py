from django import forms
from captcha.fields import CaptchaField


class CaptchaForm(forms.Form):
    captcha = CaptchaField()

class VerifyUser(forms.Form):
    username = forms.CharField()

class ForgotPasswd(forms.Form):
    username = forms.CharField()
