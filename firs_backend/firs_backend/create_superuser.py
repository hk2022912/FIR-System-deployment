import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'firs_backend.settings')
django.setup()

from django.contrib.auth.models import User

if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'operation.firs.2026@gmail.com', 'Firs2026!')
    print('Superuser created')
else:
    print('Superuser already exists')
    