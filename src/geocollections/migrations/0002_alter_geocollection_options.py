# Generated by Django 3.2.18 on 2023-09-06 07:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('geocollections', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='geocollection',
            options={'permissions': (('access_geocollection', 'Can view geocollection'),)},
        ),
    ]
