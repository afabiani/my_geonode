# Generated by Django 3.2.18 on 2023-09-05 10:31

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('base', '0086_resourcebase_custom_md'),
        ('groups', '0034_auto_20200512_1431'),
    ]

    operations = [
        migrations.CreateModel(
            name='Geocollection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128, unique=True)),
                ('slug', models.SlugField(max_length=128, unique=True)),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='group_collections', to='groups.groupprofile')),
                ('resources', models.ManyToManyField(related_name='resource_collections', to='base.ResourceBase')),
            ],
        ),
    ]
