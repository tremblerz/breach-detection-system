__acc_sid__=""
__token__=""
from twilio.rest import TwilioRestClient
def message(phone_number,body):
	client = TwilioRestClient(__acc_sid__,__token__)
	message = client.messages.create(to=phone_number,from_=twilio-NUMBER,body=body)
#message(number)
