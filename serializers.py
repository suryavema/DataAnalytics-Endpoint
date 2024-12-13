from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserCSVFile

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        extra_kwargs = {'email': {'required': True}}

class UserCSVFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCSVFile
        fields = '__all__'