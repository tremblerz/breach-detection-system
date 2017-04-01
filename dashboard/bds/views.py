from django.shortcuts import render

# Create your views here.
def index(request):
	data="some data re!"
	return render(request,'bds/index.html',{'data':data})
