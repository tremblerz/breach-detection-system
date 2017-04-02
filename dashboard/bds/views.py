from django.shortcuts import render,redirect
import random,json
from django.http import HttpResponse
from django.contrib.auth import authenticate,logout,login
from bds.models import Packet,CT
from smtplib import SMTP
# Create your views here.

import urllib2
import cookielib
import sys


def sendmsg(username,password,receivers,msg):
    url = 'http://site24.way2sms.com/Login1.action?'
    data = 'username='+username+'&password='+password+'&Submit=Sign+in'
    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    opener.addheaders = [('User-Agent','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36')]
    try:
        opener.open(url, data)
    except IOError:
        print "Error while logging in."
        sys.exit(1)
    session_id = str(cj).split('~')[1].split(' ')[0]
    send_sms_url = 'http://site24.way2sms.com/smstoss.action?'
    for number in receivers:
        send_sms_data = 'ssaction=ss&Token='+str(session_id)+'&mobile='+str(number)+'&message='+msg+'&msgLen=136'
        opener.addheaders = [('Referer', 'http://site25.way2sms.com/sendSMS?Token='+session_id)]
        try:
            opener.open(send_sms_url,send_sms_data)
        except IOError:
            print "Error while sending message"
            


"""
def rev_data(request):
	smtpobj = smtplib.SMTP('smtp.gmail.com',587)
	smtpobj.starttls()
	smtpobj.login("sriharsha.g15@iiits.in",'ibSriHarshaG1')
	if request.method=="POST":
		#handling the request here and database entry
		if var1.breach_confidence>60:
			smtpobj.sendmail('sriharsha.g15@iiits.in','murali.v15@iiits.in',"Breach Detected! please Check the BDS System")
			sendmsg("7032636850","1997",[9100753548],"Breach Detected From ip.addr!!")
			smtpobj.loguot
"""
def login_v(request):
	message = ""
	if request.method == "POST":
		user_n = request.POST["usern"]
		passw = request.POST["passw"]
		user = authenticate(username=user_n,password=passw)
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
	count={'nor' : 0, 'sus' : 0, 'mal' : 0}
	k=0
	if request.user.is_authenticated:
		name = request.user
		all_obj = Packet.objects.all()
		for i in all_obj:
			if i.breach_confidence<30:
				count["nor"] += 1
			elif 30<=i.breach_confidence<60:
				count["sus"] += 1
			else:
				count["mal"] += 1
			val.append([k+1,i.timestamp,i.srcIP,i.desIP,i.Com_MAC])
			k+=1
	else:
		return redirect('login')
	return render(request,'bds/index.html',{'name':name,'val':val,'count':count})
def map_data(request):
	if request.method=="POST":
		coun = CT.objects.all()
		val=[]
		for i in coun:
			val.append({"code":i.cod,"name":i.srcIP,"value":i.breach_confidence})
		val=json.dumps(val)
		return HttpResponse(val,content_type='application/json')
def confirmed(request):
	if request.method=="POST":
		data = json.dumps(latlong)
		return HttpResponse(data,content_type="application/json")
	return render(request, 'bds/confirmed.html')

def suspicious(request):
	return render(request, 'bds/suspicious.html')

def TopThreats(request):
	return render(request, 'bds/TopThreats.html')

def valueret(request):
	all_obj = Packet.objects.all()
	val = []
	dic = {}
	for i in all_obj:
		if i.timestamp.strftime("%b") in dic:
			if i.breach_confidence<30:
				dic[i.timestamp.strftime("%b")]["nor"] += 1
			elif 30<=i.breach_confidence<60:
				dic[i.timestamp.strftime("%b")]["sus"] += 1
			else:
				dic[i.timestamp.strftime("%b")]["mal"] += 1
		else:
			dic[i.timestamp.strftime("%b")] = {"nor":0,"sus":0,"mal":0}
			if i.breach_confidence<30:
				dic[i.timestamp.strftime("%b")]["nor"] += 1
			elif 30<=i.breach_confidence<60:
				dic[i.timestamp.strftime("%b")]["sus"] += 1
			else:
				dic[i.timestamp.strftime("%b")]["mal"] += 1
	for i in dic:
		val.append({"year":i,"nor":dic[i]["nor"],"sus":dic[i]["sus"],"mal":dic[i]["mal"]})
	val=json.dumps(val)
	return HttpResponse(val,content_type='application/json')
	