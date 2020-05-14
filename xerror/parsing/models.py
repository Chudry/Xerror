from django.db import models

from django.utils import timezone



class Job(models.Model):
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateTimeField(default=timezone.now)
    completed = models.DateTimeField(null=True, blank=True)
    celery_id = models.CharField(max_length=255, null=True, blank=True)

    exploit_lock = models.CharField(max_length=255,default="no")

    nm_status = models.CharField(max_length=255,default="no")
    vul_status = models.CharField(max_length=255,default="no")
    exploit_status = models.CharField(max_length=255,default="Exploit")

    exploit_config = models.CharField(max_length=255,default="no")

    opv_scan_id   = models.CharField(max_length=255,default="no")
    opv_target_id = models.CharField(max_length=255,default="no")
    opv_report_id = models.CharField(max_length=255,default="no")


    class Meta:
        ordering = ('created',)

    def __unicode__(self):
        return self.name


class Config_exploit(models.Model):
    config_host_name    = models.CharField(max_length=255)
    config_host_id      = models.CharField(max_length=255)
    config_cve_number   = models.CharField(max_length=255, null=True, blank=True)
    config_exploit_name = models.CharField(max_length=255, null=True, blank=True)
    config_payload_name = models.CharField(max_length=255, null=True, blank=True)
    config_rhost        = models.CharField(max_length=255, null=True, blank=True)
    config_rport        = models.CharField(max_length=255, null=True, blank=True)


class Exploiated_system(models.Model):
    host_name = models.CharField(max_length=255)
    cve_number = models.CharField(max_length=255, null=True, blank=True)
    exploit_name = models.CharField(max_length=255, null=True, blank=True)
    payload_name = models.CharField(max_length=255, null=True, blank=True)
    host_id = models.CharField(max_length=255, null=True, blank=True)
    
    exploit_rport = models.CharField(max_length=255,default="0000")
    exploited = models.CharField(max_length=255,default="no")
    session_id = models.CharField(max_length=255,default="no")

    exploit_uuid     = models.CharField(max_length=255, null=True, blank=True)
    session_type = models.CharField(max_length=255, null=True, blank=True)
    tunnel_peer = models.CharField(max_length=255, null=True, blank=True)

    created = models.DateTimeField(default=timezone.now)
    completed = models.DateTimeField(null=True, blank=True)


    class Meta:
        ordering = ('created',)

    def __unicode__(self):
        return self.host_name



class MSF_rpc_connection(models.Model):
    rpc_uname    = models.CharField(max_length=255)
    rpc_pass      = models.CharField(max_length=255)
    rpc_ip   = models.CharField(max_length=255)


class openvas_connection(models.Model):
    opv_uname    = models.CharField(max_length=255)
    opv_pass     = models.CharField(max_length=255)
    opv_ip       = models.CharField(max_length=255)





class TextFile(models.Model):
    name = models.CharField(max_length=255)
    amount = models.IntegerField(null=True, blank=True)
    file = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    completed = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ('created',)

    def __unicode__(self):
        return self.name
