from django.shortcuts import render,redirect

# Create your views here.
def index(request):
	data="some data re!"
	return render(request,'bds/index.html',{'data':data})
def confirmed(request):
	return render(request, 'bds/confirmed.html')
def suspicious(request):
	return render(request, 'bds/suspicious.html')
def TopThreats(request):
	return render(request, 'bds/TopThreats.html')

