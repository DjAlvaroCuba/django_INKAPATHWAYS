from django.contrib.auth import logout
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import RegisterForm, LoginForm
import requests
from rest_framework.authtoken.models import Token
from django.middleware.csrf import get_token
    
#from django.views.decorators.csrf import csrf_exempt /#Usar en caso de problemas con el fronted en el csrf de django

from django.contrib.auth.models import User
def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            data = {
                'username': form.cleaned_data['username'],
                'password': form.cleaned_data['password']
            }
            response = requests.post('http://localhost:8000/api/register/', data=data)
            if response.status_code == 201:
                return redirect('/test/login/')
            else:
                error = response.json().get('error')
                messages.error(request, error)
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            data = {
                'username': form.cleaned_data['username'],
                'password': form.cleaned_data['password']
            }
            response = requests.post('http://localhost:8000/api/login/', data=data)
            if response.status_code == 200:
                token = response.json().get('Token')
                request.session['token'] = token

                # Generar un nuevo token de autenticación y asociarlo al usuario
                
                user = User.objects.get(username=form.cleaned_data['username'])
                Token.objects.filter(user=user).delete()  # Eliminar tokens anteriores
                new_token = Token.objects.create(user=user)  # Generar nuevo token
                request.session['auth_token'] = new_token.key  # Almacenar el nuevo token en la sesión

                return redirect('/test/profile/')
            else:
                error = response.json().get('error')
                messages.error(request, error)
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

def profile_view(request):
    token = request.session.get('auth_token')
    if not token:
        return redirect('/test/login/')
    
    # Verifica si el token de autenticación es válido
    try:
        token_obj = Token.objects.get(key=token)
        user = token_obj.user
    except Token.DoesNotExist:
        return redirect('/test/login/')
    
    csrf_token = get_token(request)
    headers = {
        'Authorization': f'Token {token}',
        'X-CSRFToken': csrf_token
    }
    
    return render(request, 'profile.html', {'username': user.username})

def logout_view(request):
    if request.method == 'POST':
        # Cerrar sesión
        logout(request)
    return redirect('/test/login/')
def home(request):
    return render(request, 'home.html')