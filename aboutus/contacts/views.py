from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

class LoggedInMixin(object):

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(LoggedInMixin, self).dispatch(*args, **kwargs)

class ListContactView(LoggedInMixin, ListView):

    model = Contact
    template_name = 'contact_list.html'

    def get_queryset(self):

        return Contact.objects.filter(owner=self.request.user)


