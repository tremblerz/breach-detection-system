from django.conf.urls import url
from . import views
urlpatterns=[
	url(r'^$',views.index,name="index"),
	url(r'^confirmed', views.confirmed, name="confirmed"),
	url(r'^suspicious', views.suspicious, name="suspicious"),
	url(r'^TopThreats', views.TopThreats, name="TopThreats"),
	url(r'^login',views.login_v,name="login"),
	url(r'^logout',views.logout_v,name='logout'),
    url(r'^random',views.valueret,name='random'),
]
