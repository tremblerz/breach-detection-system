from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,logout,login
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
	return render(request,'login_v.html',{'message':message})

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

