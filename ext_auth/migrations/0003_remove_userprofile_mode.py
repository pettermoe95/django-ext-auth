# Generated by Django 4.1 on 2022-12-20 12:57

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ext_auth', '0002_userprofile_display_name_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='mode',
        ),
    ]
