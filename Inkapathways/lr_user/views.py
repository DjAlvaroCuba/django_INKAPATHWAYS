from rest_framework.decorators import api_view
from rest_framework.response import Response
from . serializers import UserSerializer
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

@api_view(['POST'])
def login(request):
    # Lógica para el inicio de sesión

    user = get_object_or_404(User, username = request.data['username'])

    if not user.check_password(request.data['password']):
        return Response({"error": "Invalid password"} , status = status.HTTP_400_BAD_REQUEST)
    token , created= Token.objects.get_or_create(user=user)

    serializer = UserSerializer(instance=user)

    return Response({"Token": token.key, "User":serializer.data}, status = status.HTTP_200_OK)

@api_view(['POST'])
def register(request):
    # Lógica para el registro de usuarios
    serializer = UserSerializer(data = request.data)
    if serializer.is_valid():
        serializer.save()

        user = User.objects.get(username= serializer.data['username'])
        user.set_password(serializer.data['password'])
        user.save()
        print(request.data)

        token = Token.objects.create(user=user)
        return Response ({'token': token.key , "User" : serializer.data} , status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#STATUS --> 200 PARA EL OK 
#       -->  

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def profile(request):
    # Lógica para obtener el perfil del usuario
    print(request.user)

    return Response("Tu estas logueado con {}". format(request.user.username), status=status.HTTP_200_OK)
