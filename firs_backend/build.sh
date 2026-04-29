#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate
python manage.py shell -c "
from django.contrib.auth.models import User
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'operation.firs.2026@gmail.com', 'Firs2026!')
    print('Superuser created')
else:
    print('Superuser already exists')
"
"