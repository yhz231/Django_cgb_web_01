from django.db import models

# Create your models here.


class ObjectPolicy(models.Model):
    uuid = models.CharField(max_length=255)
    original_acl = models.CharField(max_length=255)

class TimeRange(models.Model):
    name = models.CharField(max_length=50)
    end_datetime = models.DateTimeField()
    firewall_name = models.CharField(max_length=50)

class AccessGroup(models.Model):
    access_group = models.CharField(max_length=50)
    interface = models.CharField(max_length=50)
    firewall_name = models.CharField(max_length=50)

class Policy(models.Model):
    firewall_name = models.CharField(max_length=50)
    protocol = models.CharField(max_length=20)
    interface = models.CharField(max_length=100)
    original_acl = models.CharField(max_length=255)
    line_no = models.PositiveIntegerField()
    has_objectgroup = models.BooleanField(blank=False)
    src_ip = models.GenericIPAddressField(protocol='ipv4')
    src_mask = models.CharField(max_length=100)
    src_port_low = models.PositiveIntegerField(default=0)
    src_port_high = models.PositiveIntegerField(default=65535)
    dst_ip = models.GenericIPAddressField(protocol='ipv4')
    dst_mask = models.CharField(max_length=100)
    dst_port_low = models.PositiveIntegerField(default=0)
    dst_port_high = models.PositiveIntegerField(default=65535)
    action = models.CharField(max_length=20)
    time_range = models.CharField(max_length=50)
    hitcnt = models.PositiveIntegerField(default=0)
    uuid = models.CharField(max_length=200)








