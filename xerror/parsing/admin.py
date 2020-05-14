from django.contrib import admin

from .models import TextFile,Job,Exploiated_system,Config_exploit,MSF_rpc_connection,openvas_connection
admin.site.register(TextFile)
admin.site.register(Job)
admin.site.register(Exploiated_system)
admin.site.register(Config_exploit)
admin.site.register(MSF_rpc_connection)
admin.site.register(openvas_connection)
