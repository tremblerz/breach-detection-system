from django.shortcuts import render,redirect
import random,json
from django.http import HttpResponse
from django.contrib.auth import authenticate,logout,login
from bds.models import Packet
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
	val=[]
	if request.user.is_authenticated:
		name=request.user
		all_obj = Packet.objects.all()
		for i in all_obj:
			val.append([i.timestamp,i.srcIP,i.desIP,i.Com_MAC])
	else:
		return redirect('login')
	return render(request,'bds/index.html',{'name':name,'val':val})

def confirmed(request):	
	return render(request, 'bds/confirmed.html')

def suspicious(request):
	return render(request, 'bds/suspicious.html')

def TopThreats(request):
	return render(request, 'bds/TopThreats.html')

def valueret(request):
	all_obj = Packet.objects.all()
	val=[]
	dic={}
	for i in all_obj:
		if i.timestamp.strftime("%b") in dic:
			if i.breach_confidence<30:
				dic[i.timestamp.strftime("%b")]["nor"]+=1
			elif 30>=i.breach_confidence<60:
				dic[i.timestamp.strftime("%b")]["sus"]+=1
			else:
				dic[i.timestamp.strftime("%b")]["mal"]+=1
		else:
			dic[i.timestamp.strftime("%b")]={"nor":0,"sus":0,"mal":0}
			if i.breach_confidence<30:
				dic[i.timestamp.strftime("%b")]["nor"]+=1
			elif 30>=i.breach_confidence<60:
				dic[i.timestamp.strftime("%b")]["sus"]+=1
			else:
				dic[i.timestamp.strftime("%b")]["mal"]+=1
	for i in dic:
		val.append({"year":i,"nor":dic[i]["nor"],"sus":dic[i]["sus"],"mal":dic[i]["mal"]})
	val=json.dumps(val)
	return HttpResponse(val,content_type='application/json')
	