from django.db import models

# Create your models here.


class FWUser(models.Model):
    name = models.CharField(max_length=50, blank=True)
    acs_account = models.CharField(max_length=50, blank=True)
    ad_account = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return self.name


class FWResult(models.Model):
    safe_matrix_acl = models.IntegerField(default=0)
    rubbish_acl = models.IntegerField(default=0)
    any_acl = models.IntegerField(default=0)
    hight_danger_acl = models.IntegerField(default=0)
    no_registered_acl = models.IntegerField(default=0)
    name = models.CharField(max_length=50)
    rank = models.IntegerField(default=0)
    display_row = models.IntegerField(default=0)

    def __str__(self):
        return self.name


class FWTempResult(models.Model):
    safe_matrix_acl = models.IntegerField(default=0)
    rubbish_acl = models.IntegerField(default=0)
    any_acl = models.IntegerField(default=0)
    hight_danger_acl = models.IntegerField(default=0)
    no_registered_acl = models.IntegerField(default=0)
    name = models.CharField(max_length=50)
    rank = models.IntegerField(default=0)
    display_row = models.IntegerField(default=0)

    def __str__(self):
        return self.name


class FWAccount(models.Model):
    inputer = models.CharField(max_length=50)
    firewall = models.CharField(max_length=50, blank=True)
    type = models.CharField(max_length=50, blank=True)
    firemon_original = models.TextField(blank=True)
    firemon_handle = models.TextField(blank=True)
    firemon_final = models.TextField(blank=True)
    expire = models.CharField(max_length=50)
    executor = models.ForeignKey(FWUser, verbose_name='username')
    exec_time = models.DateTimeField(blank=True)
    order = models.CharField(max_length=50)
    requirement = models.TextField()
    dissidence = models.CharField(max_length=50)
    other = models.TextField()

    def __str__(self):
        return self.executor