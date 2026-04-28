from django.db import models
from django.utils import timezone

class Incident(models.Model):
    INVOLVED_CHOICES = [
        ('Structural', 'Structural'),
        ('Non-Structural', 'Non-Structural'),
        ('Vehicular', 'Vehicular'),
    ]
    ALARM_CHOICES = [
        ('1st Alarm', '1st Alarm'), ('2nd Alarm', '2nd Alarm'),
        ('3rd Alarm', '3rd Alarm'), ('4th Alarm', '4th Alarm'),
        ('5th Alarm', '5th Alarm'), ('EUA', 'EUA'),
        ('FOA', 'FOA'), ('FOUA', 'FOUA'), ('N/A', 'N/A'),
    ]

    dt       = models.CharField(max_length=100)
    loc      = models.TextField()
    inv      = models.CharField(max_length=20, choices=INVOLVED_CHOICES)
    occ      = models.CharField(max_length=200)
    dmg_raw  = models.BigIntegerField(default=0)
    alarm    = models.CharField(max_length=20, choices=ALARM_CHOICES)
    sta      = models.CharField(max_length=100)
    eng      = models.CharField(max_length=100)
    by_user  = models.CharField(max_length=200)
    inj_c    = models.IntegerField(default=0)
    inj_b    = models.IntegerField(default=0)
    cas_c    = models.IntegerField(default=0)
    cas_b    = models.IntegerField(default=0)
    rem      = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"{self.dt} — {self.loc}"


class PasswordResetOTP(models.Model):
    user       = models.OneToOneField('auth.User', on_delete=models.CASCADE, related_name='reset_otp')
    otp        = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"OTP for {self.user.email}"