from django.shortcuts import render,redirect
import random,json
from django.http import HttpResponse
from django.contrib.auth import authenticate,logout,login
#import Packet.models
# Create your views here.
def login_v(request):
	message=""
	if request.method=="POST":
		user_n = request.POST["usern"]
		passw = request.POST["passw"]
		user=authenticate(username=user_n,password=passw)
		if user is not None:
			login(request,user)
			return redirect("index")
		else:
			message="Wromg Credentials"
	return render(request,'bds/login_v.html',{'message':message})

def logout_v(request):
	logout(request)
	return redirect('login')

def index(request):
	if request.user.is_authenticated:
		name=request.user
	else:
		return redirect('login')
	return render(request,'bds/index.html',{'name':name})

def confirmed(request):	
	return render(request, 'bds/confirmed.html')

def suspicious(request):
	return render(request, 'bds/suspicious.html')

def TopThreats(request):
	return render(request, 'bds/TopThreats.html')
def valueret(request):
	temp=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sept","Oct","Nov","Dec"]
	val=[]
	if request.method=="POST":
		for i in temp:
			val.append({"year":i,"mal":random.randint(1,10**5),"sus": random.randint(1,10**5),"nor": random.randint(1,10**5)})
	val=json.dumps(val)
	return HttpResponse(val,content_type='application/json')