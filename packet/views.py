from django.http import HttpResponse
from django.http.response import FileResponse, Http404, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.db.models.query_utils import Q
from django.shortcuts import render
from database.models import *

def index(request):
    if request.method == 'GET':
        return HttpResponseRedirect('/login/')
    else:
        return Http404()

def login(request):
    if request.method == 'GET':
        return render(request, 'packet/login.html')
    elif request.method == 'POST':
        account = request.POST.get('account')
        password = request.POST.get('password')
        ad = Administor(account=account,password=password)
        admin = Administor.objects.filter(Q(account=account) & Q(password=password))
        print(admin)
        if admin.count() != 0:
            request.session['user'] = 'admin'
            request.session['user_id'] = admin[0].account
            return HttpResponseRedirect('/main/')
        user = User.objects.filter(Q(account=account) & Q(password=password))
        if user.count() != 0:
            request.session['user'] = 'user'
            request.session['user_id'] = user[0].account
            return HttpResponseRedirect('/main/')
    else:
        return Http404()

def register(request):
    if request.method == 'GET':
        return render(request, 'packet/register.html')
    if request.method == 'POST':
        account = request.POST.get('account')
        password = request.POST.get('password')
        actor = request.POST.get('actor')
        if actor=='管理员':
            admin = Administor.objects.filter(account=account)
            if admin.count() == 0:
                admin = Administor(account=account,password=password)
                admin.save()
                return HttpResponseRedirect('/login/')
            else:
                info = {'info':'此用户已存在'}
                return render(request,'packet/register.html',info)
        elif actor=='普通用户':
            user = User.objects.filter(account=account)
            if user.count() == 0:
                user = User(account=account,password=password)
                user.save()
                return HttpResponseRedirect('/login/')
            else:
                x = {'info':'此用户已存在'}
                return render(request,'packet/register.html',x)
        else:
            return Http404()

def main(request):
    user = request.session['user']
    user_id = request.session['user_id']

    if user == 'admin':
        user = Admin.objects.filter(account=user_id)[0]
        context = {
            'actor': 'admin',
            'user': user
        }
    elif user == 'user':
        user = User.objects.filter(account=user_id)[0]
        context = {
            'actor': 'user',
            'user': user
        }
    return render(request, 'packet/main.html', context)


