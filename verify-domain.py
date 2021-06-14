import base64
import hashlib
import hmac
import uuid
import datetime
import requests
 
# Setup required variables
base_url = "https://de-api.mimecast.com"
uri = "/api/domain/verify-domain"
url = base_url + uri
access_key = "mYtOL3XZCOwG96BOiFTZRt7fhZtq-x82SIg5sM6CxxM58tZHBdHLpm0OOyLfPCH-dPTgQTVgfCGM4mTGVC9H8-oPpmGoSnhTFtHBbyPiNArfcbmO5URXphWHGQzIWoOxWTEbk9e34FIrLq76NC3SQxU1_Kb8FER8gadNhl04PJA"
secret_key = "X8S8vEHJvHcQWRmJMfJW/HxvNHQ2uaarabhXDAsNI5eJE8/F0uqyXK18qono/VeXmU/rsNg7KIRjI2nYBfX16A=="
app_id = "6bc915fe-5da2-4f0b-8fa7-8d8d2c1e8c98"
app_key = "4983ba98-6054-4d52-9954-19f579b4945f"
 
# Generate request header values
	
request_id = str(uuid.uuid4())
	
hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
	
 
	
# DataToSign is used in hmac_sha1
	
dataToSign = ':'.join([hdr_date, request_id, uri, app_key])
	
 
	
# Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
	
hmac_sha1 = hmac.new(base64.b64decode(secret_key), dataToSign.encode(), digestmod=hashlib.sha1).digest()
	
 
	
# Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
	
sig = base64.b64encode(hmac_sha1).rstrip()
	
  
# Create request headers
headers = {
    'Authorization': 'MC ' + access_key + ':' + sig.decode(),
    'x-mc-app-id': app_id,
    'x-mc-date': hdr_date,
    'x-mc-req-id': request_id,
    'Content-Type': 'application/json'
}
 
payload = {
 "data": [
     {
         "domain": "triviummeulenbeltzorg.nl",
         "inboundType": "any"
     }
 ]
}
 
r = requests.post(url=url, headers=headers, data=str(payload))
 
print (r.text)
