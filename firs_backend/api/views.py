from django.shortcuts import render

from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate

from .models import Incident
from .serializers import IncidentSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({
        'token': token.key,
        'display': user.get_full_name() or user.username,
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    request.user.auth_token.delete()
    return Response({'message': 'Logged out'})

class IncidentViewSet(viewsets.ModelViewSet):
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get_queryset(self):
        return Incident.objects.all().order_by('created_at')

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def bulk_import(request):
    records = request.data.get('records', [])
    created = []
    for rec in records:
        serializer = IncidentSerializer(data={
            'dt':      rec.get('dt', ''),
            'loc':     rec.get('loc', ''),
            'inv':     rec.get('inv', ''),
            'occ':     rec.get('occ', ''),
            'dmg_raw': rec.get('dmgRaw', 0),
            'alarm':   rec.get('alarm', ''),
            'sta':     rec.get('sta', ''),
            'eng':     rec.get('eng', ''),
            'by_user': rec.get('by', ''),
            'inj_c':   rec.get('injC', 0),
            'inj_b':   rec.get('injB', 0),
            'cas_c':   rec.get('casC', 0),
            'cas_b':   rec.get('casB', 0),
            'rem':     rec.get('rem', ''),
        })
        if serializer.is_valid():
            created.append(serializer.save())
    return Response({'imported': len(created)}, status=status.HTTP_201_CREATED)



from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings

# ── Existing views (login, logout, bulk_import, IncidentViewSet) stay unchanged ──


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    """
    Accepts { "email": "user@example.com" }
    Sends a password-reset link if the email exists.
    Always returns 200 to avoid leaking whether an email is registered.
    """
    email = request.data.get('email', '').strip()

    if not email:
        return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        # Return 200 anyway — don't reveal whether the email exists
        return Response({'message': 'If that email is registered, a reset link has been sent.'})

    # Build the reset token + uid
    uid   = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

    subject = 'Password Reset — Fire Incident Recording System'
    body = f"""Hello {user.get_full_name() or user.username},

You requested a password reset for your FIRS account.

Click the link below to set a new password (valid for 1 hour):
{reset_url}

If you did not request this, you can safely ignore this email.

— FIRS System
"""

    send_mail(
        subject,
        body,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )

    return Response({'message': 'If that email is registered, a reset link has been sent.'})


@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    """
    Accepts { "uid": "...", "token": "...", "new_password": "..." }
    Validates the token and updates the password.
    """
    uid          = request.data.get('uid', '')
    token        = request.data.get('token', '')
    new_password = request.data.get('new_password', '')

    if not all([uid, token, new_password]):
        return Response({'error': 'uid, token, and new_password are all required.'}, status=status.HTTP_400_BAD_REQUEST)

    if len(new_password) < 8:
        return Response({'error': 'Password must be at least 8 characters.'}, status=status.HTTP_400_BAD_REQUEST)

    # Decode uid → user
    try:
        user_pk = force_str(urlsafe_base64_decode(uid))
        user    = User.objects.get(pk=user_pk)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'error': 'Invalid reset link.'}, status=status.HTTP_400_BAD_REQUEST)

    # Validate token
    if not default_token_generator.check_token(user, token):
        return Response({'error': 'Reset link is invalid or has expired.'}, status=status.HTTP_400_BAD_REQUEST)

    # Set the new password
    user.set_password(new_password)
    user.save()

    # Invalidate any existing auth tokens so old sessions are kicked out
    Token.objects.filter(user=user).delete()

    return Response({'message': 'Password updated successfully. You can now log in.'})