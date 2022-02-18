from django.shortcuts import render
from django.http.response import Http404, HttpResponse, JsonResponse
from database.models import *

# Create your views here.
def listRequests(request):
    requests = list(Request.objects.all())
    datas = []
    for i in requests:
        data = []
        data.append(i.id)
        data.append(i.src_ip)
        data.append(i.dst_ip)
        data.append(i.src_port)
        data.append(i.dst_port)
        data.append(i.host)
        data.append(i.uri)
        data.append(i.user_agent)
        data.append(i.cookie)
        data.append(i.frame_length)
        data.append(i.path)
        datas.append(data)
    if len(datas) != 0:
        return JsonResponse(datas, safe=False)
    else:
        return HttpResponse(0)

def listResponses(request):
    responses = list(Response.objects.all())
    datas = []
    for i in responses:
        data = []
        data.append(i.id)
        data.append(i.src_ip)
        data.append(i.dst_ip)
        data.append(i.src_port)
        data.append(i.dst_port)
        data.append(i.content_type)
        data.append(i.frame_length)
        data.append(i.path)
        datas.append(data)
    if len(datas) != 0:
        return JsonResponse(datas, safe=False)
    else:
        return HttpResponse(0)

def listProperty(request):
    nums = [1,2,3,4,2]
    data = {'num':nums}
    return JsonResponse(data,safe=False)

def listRequestType(request):
    requests = list(Request.objects.all())
    nums = [0,0,0]
    for i in requests:
        if i.uri.split(' ')[0] == "GET":
            nums[0]+=1
        elif i.uri.split(' ')[0] == "POST":
            nums[1]+=1
        elif i.uri.split(' ')[0] == "GET":
            nums[2]+=1
    data = {'num':nums}
    return JsonResponse(data,safe=False)

def listRequestFrameLengthInfo(request):
    requests = list(Request.objects.all())
    max_len = 0
    min_len = 2147483647
    total_len = 0
    avg_len = 0
    for i in requests:
        total_len += i.frame_length
        max_len = max(max_len,i.frame_length)
        min_len = min(min_len,i.frame_length)
    avg_len = total_len/len(requests)
    print(max_len)
    print(min_len)
    print(avg_len)
    data = []
    data.append(max_len)
    data.append(min_len)
    data.append(avg_len)
    return JsonResponse(data,safe=False)

def listResponseFrameLengthInfo(request):
    responses = list(Response.objects.all())
    max_len = 0
    min_len = 2147483647
    total_len = 0
    avg_len = 0
    for i in responses:
        total_len += i.frame_length
        max_len = max(max_len,i.frame_length)
        min_len = min(min_len,i.frame_length)
    avg_len = total_len/len(responses)
    print(max_len)
    print(min_len)
    print(avg_len)
    data = []
    data.append(max_len)
    data.append(min_len)
    data.append(avg_len)
    return JsonResponse(data,safe=False)

def listSrcIpNum(request):
    requests = list(Request.objects.all())
    data = {}
    for i in requests:
        if i.src_ip != data.keys():
            data[i.src_ip] = 1
        else:
            data[i.src_ip] = data[i.src_ip]+1
    print(data)
    return JsonResponse(data,safe=False)

def listDstIpNum(request):
    responses = list(Response.objects.all())
    data = {}
    for i in responses:
        if i.src_ip not in data.keys():
            data[i.src_ip] = 1
        else:
            data[i.src_ip]+=1
    print(data)
    return JsonResponse(data,safe=False)