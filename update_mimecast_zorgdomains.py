#!/usr/bin/python3

# update_mimecast_zorgdomains.py
# Copyright (C) 2020-2021 Deltics

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import base64
import hashlib
import hmac
import uuid
import datetime
import time
import sys
import requests
import re
import pprint
import urllib
import argparse
import configparser



pp = pprint.PrettyPrinter(indent = 4)



def argsparser ():
        parser = argparse.ArgumentParser()
        parser.add_argument("-v", "--verbose", help = "be verbose", action = "store_true")
        parser.add_argument("-c", "--config_file", help = "config file", required=True)
        return parser.parse_args()

args = argsparser()

logfile = args.config_file + ".log"
log = open(logfile, "w")


config = configparser.ConfigParser()
config.read(args.config_file)

#pp.pprint (config['default']['base_url'])


domainbook_url = config['default']['domainbook_url']
base_url = config['default']['base_url']

access_key = config['default']['access_key']
secret_key = config['default']['secret_key']
app_id = config['default']['app_id']
app_key = config['default']['app_key']

group = config['default']['group']

exclude_list = config['default']['exclude']
exclude = exclude_list.split ()



f = urllib.request.urlopen(domainbook_url)
webpage = f.read()
webpage = webpage.decode("utf-8")
f.close()
webpage = re.sub ("###.*\n", '', webpage)
zorgmail_domains = webpage.split()
#pp.pprint (zorgmail_domains)



# Setup required variables
uri = "/api/directory/find-groups"
url = base_url + uri
 
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
        'meta': {
            'pagination': {
                'pageSize': 25,
                'pageToken': ''
            }
        },
        'data': [
            {
                'query': group,
                'source': 'cloud'
            }
        ]
    }

r = requests.post(url=url, headers=headers, data=str(payload))

result = r.json ()

#pp.pprint (result);

folder_id = result ['data'][0]['folders'][0]['id']

# print (folder_id)

uri = "/api/directory/get-group-members"

url = base_url + uri

 
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

domains = []

next = ''
while True:
    payload = {
            'meta': {
                'pagination': {
                    'pageSize': 25,
                    'pageToken': next
                }
            },
            'data': [
                {
                    'id': folder_id
                }
            ]
        }
    r = requests.post(url=url, headers=headers, data=str(payload))

    result = r.json ()
    groupMembers =  result['data'][0]['groupMembers']
#    print ("groupmembers: ")
#    pp.pprint (groupMembers)

    for address in groupMembers:
        domains.append (address['domain'])
#        print (address['domain'])

    if ('next' in result ['meta']['pagination']):
        next = result ['meta']['pagination']['next']
    else:
        break

#pp.pprint (domains)

#print ("exclude:")
#pp.pprint (exclude)

remove = list (set (domains) - set (zorgmail_domains))
remove = list (set (remove) | set (exclude))

#print ("remove:")
#pp.pprint (remove)
log.write ("removing domains:\n")
log.write ('\n '.join (remove))

add = list (set (zorgmail_domains) - set (domains))
add = list (set (add) - set (exclude))

#print ("add:")
#pp.pprint (add)
log.write ("\n\nadding domains:\n")
log.write ('\n '.join (add))
log.write ("\n\n")

uri = "/api/directory/remove-group-member"
url = base_url + uri


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


for domain in remove:
#    print ("remove: " + domain)
    payload = {
        'data': [
            {
                'id': folder_id,
#                'emailAddress': domain,
                'domain': domain
            }
        ]
    }

    r = requests.post(url=url, headers=headers, data=str(payload))
#    pp.pprint (r.text)


uri = "/api/directory/add-group-member"
url = base_url + uri

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


cnt = 0;
for domain in add:
#    print ("add: "+ domain)
    payload = {
        'data': [
            {
                'id': folder_id,
#                'emailAddress': '',
                'domain': domain
            }
        ]
    }
    if cnt <= 1000: # make new header
        cnt = 0
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


    r = requests.post(url=url, headers=headers, data=str(payload))
#    pp.pprint (r.headers)
#    pp.pprint (r.text)
    if r.text == 'Too Many Requests':
        log.write ("ERROR " + '\n '.join (r,headers))
        time.sleep (10)
        r = requests.post(url=url, headers=headers, data=str(payload))
        pp.pprint (r.headers)
        pp.pprint (r.text)

    r_headers = r.headers
    if int (r_headers ['X-RateLimit-Remaining']) <= 1:
            print ("sleep: " + r_headers ['X-RateLimit-Reset'])
            time.sleep (int (r_headers ['X-RateLimit-Reset']) / 1000 + 1)
    text = r.json ()
    if text['meta']['status'] != 200:
#        print ("ERROR " + str (text['meta']['status']) + str (text['data']['fail']))
        log.write ("ERROR " + str ( text['meta']['status']) + str (text['data']['fail']))
        log.write ("CRTITCAL: update for " + args.config_file + "failed\n")
        log.close()
        sys.exit(1);
log.write("OK\n")
log.close()
sys.exit(0)        
