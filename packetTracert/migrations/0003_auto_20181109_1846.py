# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2018-11-09 18:46
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('packetTracert', '0002_auto_20181109_1822'),
    ]

    operations = [
        migrations.AlterField(
            model_name='policy',
            name='time_range',
            field=models.CharField(default='', max_length=50),
            preserve_default=False,
        ),
    ]