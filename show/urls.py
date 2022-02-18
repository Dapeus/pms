from django.urls.conf import include,path
from . import views

urlpatterns = [
    path('listRequests/', views.listRequests, name='listRequests'),
    path('listResponses/', views.listResponses, name='listResponses'),
    path('listProperty/', views.listProperty, name='listProperty'),
    path('listRequestType/', views.listRequestType, name='listRequestType'),
    path('listRequestFrameLengthInfo/',views.listRequestFrameLengthInfo, name='listRequestFrameLengthInfo'),
    path('listResponseFrameLengthInfo/',views.listResponseFrameLengthInfo, name='listResponseFrameLengthInfo'),
    path('listSrcIpNum/',views.listSrcIpNum, name='listSrcIpNum'),
    path('listDstIpNum/',views.listDstIpNum, name='listDstIpNum'),
]
