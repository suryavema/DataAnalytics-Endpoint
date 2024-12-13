from django.db import models
from django.contrib.auth.models import User

class UserCSVFile(models.Model):
    """
    Model to track user's uploaded CSV files
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    table_name = models.CharField(max_length=255, unique=True)
    columns = models.JSONField()  # Store column info
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.filename}"