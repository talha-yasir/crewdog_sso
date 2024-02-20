from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class User(AbstractUser):
    first_name = models.CharField(max_length=255, null=True , blank=True)
    last_name = models.CharField(max_length=255, null=True , blank=True)
    email = models.EmailField(('email address'), unique=True)
    profile_pic = models.ImageField(upload_to='profile_image/', null=True, blank=True)
    avatar_url = models.CharField(max_length=500, blank=True , null=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name','last_name']
    
    
    def __str__(self):
        return "{}".format(self.email)

    def get_user_status(self):
        return 'Active' if self.is_active else 'Suspended'


class OTPCode(models.Model):
    code = models.CharField(max_length=6,unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    expiration_time = models.DateTimeField()

    def is_expired(self):
        return self.expiration_time < timezone.now()