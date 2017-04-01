from django.conf.urls import url
from . import views
urlpatterns=[
	url(r'^$',views.index,name="index"),
	url(r'^confirmed', views.confirmed, name="confirmed"),
	url(r'^suspicious', views.suspicious, name="suspicious"),
	url(r'^TopThreats', views.suspicious, name="TopThreats"),

]
