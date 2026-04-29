import logging
from django.shortcuts import render
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from datetime import timedelta

from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate

from .models import Incident, PasswordResetOTP
from .serializers import IncidentSerializer

logger = logging.getLogger(__name__)


# ── AUTH ──────────────────────────────────────────────────────────────────────

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


# ── INCIDENTS ─────────────────────────────────────────────────────────────────

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


# ── PASSWORD RESET (OTP FLOW) ─────────────────────────────────────────────────

@csrf_exempt
@api_view(['POST'])
@permission_classes([])
@authentication_classes([])
def forgot_password(request):
    """
    Step 1 — accepts { "email": "..." }
    Generates a 6-digit OTP, saves it to DB, and emails it to the user.
    """
    email = request.data.get('email', '').strip()

    if not email:
        return Response({'message': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        return Response({'message': 'Email not found.'}, status=status.HTTP_404_NOT_FOUND)

    otp = get_random_string(length=6, allowed_chars='0123456789')

    # Delete any existing OTP for this user, then create a fresh one
    PasswordResetOTP.objects.filter(user=user).delete()
    PasswordResetOTP.objects.create(user=user, otp=otp)

    try:
        send_mail(
            subject='FIRS — Your Password Reset Code',
            message=(
                f"Hello {user.get_full_name() or user.username},\n\n"
                f"Your verification code for the Fire Incident Recording System is:\n\n"
                f"  {otp}\n\n"
                f"This code expires in 10 minutes. Do not share it with anyone.\n\n"
                f"If you did not request this, you can safely ignore this email.\n\n"
                f"— FIRS System, Bureau of Fire Protection CDO"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
    except Exception as e:
        logger.error(f"Failed to send OTP email to {user.email}: {e}")
        return Response(
            {'message': 'Failed to send OTP. Please try again later.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)


@csrf_exempt
@api_view(['POST'])
@permission_classes([])
@authentication_classes([])
def verify_otp(request):
    """
    Step 2 — accepts { "email": "...", "otp": "123456" }
    Validates the OTP and checks it hasn't expired (10 minutes).
    """
    email = request.data.get('email', '').strip()
    otp   = request.data.get('otp', '').strip()

    if not email or not otp:
        return Response({'message': 'Email and OTP are required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user   = User.objects.get(email__iexact=email)
        record = PasswordResetOTP.objects.get(user=user)
    except (User.DoesNotExist, PasswordResetOTP.DoesNotExist):
        return Response({'message': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

    if timezone.now() - record.created_at > timedelta(minutes=10):
        record.delete()
        return Response({'message': 'OTP expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

    if record.otp != otp:
        return Response({'message': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

    return Response({'message': 'OTP verified.'}, status=status.HTTP_200_OK)


@csrf_exempt
@api_view(['POST'])
@permission_classes([])
@authentication_classes([])
def reset_password(request):
    """
    Step 3 — accepts { "email": "...", "otp": "...", "new_password": "...", "confirm_password": "..." }
    Re-validates OTP, checks passwords match, then resets the password.
    """
    email            = request.data.get('email', '').strip()
    otp              = request.data.get('otp', '').strip()
    new_password     = request.data.get('new_password', '')
    confirm_password = request.data.get('confirm_password', '')

    if not all([email, otp, new_password, confirm_password]):
        return Response({'message': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

    if new_password != confirm_password:
        return Response({'message': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)

    if len(new_password) < 8:
        return Response({'message': 'Password must be at least 8 characters.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user   = User.objects.get(email__iexact=email)
        record = PasswordResetOTP.objects.get(user=user)
    except (User.DoesNotExist, PasswordResetOTP.DoesNotExist):
        return Response({'message': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

    # Re-validate OTP one final time before committing
    if timezone.now() - record.created_at > timedelta(minutes=10):
        record.delete()
        return Response({'message': 'OTP expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

    if record.otp != otp:
        return Response({'message': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

    # All good — reset password, kick existing sessions, delete OTP
    user.set_password(new_password)
    user.save()
    Token.objects.filter(user=user).delete()
    record.delete()

    return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)