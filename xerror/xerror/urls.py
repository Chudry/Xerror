
from django.conf.urls import url, include
from django.contrib import admin
import settings

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^', include('parsing.urls')),
    url(r'^media/(?P<path>.*)$', 'django.views.static.serve',
                 {'document_root': settings.MEDIA_ROOT}),

]



