from django.conf.urls import url

from . import views


app_name = "parsing"

urlpatterns = [
    url(r'^$', views.index),
    url(r'^upload/$', views.upload),

 



# openvas 

    url(r'^openvas_scan_index/$', views.openvas_scan_index,name="openvas_scan_index"),
    url(r'^openvas_ip_detailed/(?P<id>\d+)/$', views.openvas_ip_detailed,name="openvas_ip_detailed"),
    url(r'^openvas_ajx/$', views.openvas_scan_luncher),

    url(r'^openvas_report/(?P<host_id>\d+)/$', views.vulnerability_report,name="openvas_report"),

    url(r'^nm_scan_index/$', views.nm_scan_index,name="nm_scan_index"),
    url(r'^nm_ip_detailed/(?P<id>\d+)/$', views.nm_ip_detailed,name="nm_ip_detailed"),
    url(r'^nmap_ajx/$', views.nm_scan_luncher),

# # Metasoloit 

    url(r'^msf/(?P<id>\d+)/$', views.msf_exploit,name="msf"),
    url(r'^msf_exploit_ajx/$', views.msf_exploit_vulnerability,name="msf_exploit_vulnerability"),
    url(r'^msf_exploit_config_ajx/$', views.msf_exploit_config_ajx,name="msf_exploit_config_ajx"),
    url(r'^msf_config/(?P<id>\d+)/$', views.exploit_config,name="msf_config"),
    #url(r'^msf/(?P<id>\d+)/$', views.msf_exploit,name="msf"),

    url(r'^msf_session/(?P<id>\d+)/$', views.msf_session,name="msf_session"),
    url(r'^msf_session_status_check_ajax/$', views.msf_session_status_check_ajax,name="msf_session_status_check_ajax"),

    url(r'^msf_session_intract/(?P<session_id>\w+)/(?P<host_id>\w+)/(?P<uuid>\w+)/$', views.msf_session_intract, name='msf_session_intract'),
    url(r'^msf_session_intract_ajx/$', views.msf_session_intract_ajx, name='msf_session_intract_ajx'),

# connection 

    url(r'^msf_rpc_connect/$', views.msf_rpc_connect, name='msf_rpc_connect'),
    url(r'^opv_rpc_connect/$', views.opv_rpc_connect, name='opv_rpc_connect'),

]

 # 
  



