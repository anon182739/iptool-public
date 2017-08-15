#!/usr/bin/env python3.4
import requests, json, sys, pickle, time

#hasBeenChecked = pickle.load(open("save.p", "rb"))
hasBeenChecked = {} #after first run uncomment the above line and comment this one instead
lastTime = 0


def isAdmiralDomain(domain):
    try:
        response = requests.get('http://' + domain, timeout=6) #use http because the timeout handling doesn't play nice with https
    except:
        return False
    if len(response.text) == 179:
        return True
    else:
	return False

def getReverseDns(ip):
    global lastTime
    if time.time() - lastTime < 10:
        time.sleep(10 - (time.time() - lastTime))
    apiResponse = requests.get("https://www.threatcrowd.org/searchApi/v2/ip/report/", params = {"ip": ip})
    lastTime = time.time()
    return apiResponse.json()

def getIpAddresses(domain):
    global lastTime
    if time.time() - lastTime < 10:
        time.sleep(10 - (time.time() - lastTime))
    apiResponse = requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params = {"domain": domain})
    return apiResponse.json()

def processDomain(domain):
    print("torsocks checking domain " + domain)
    print("torsocks has " + domain + " been checked before? " + str(hasBeenChecked.get(domain, False)))
    if hasBeenChecked.get(domain, False):
        return False
    print("torsocks domain has not been checked")
    if not isAdmiralDomain(domain):
        return False
    print("torsocks domain is admiral domain")
    print(domain)
    hasBeenChecked[domain] = True
    for key in getIpAddresses(domain)[u'resolutions']:
        processIpAddress(key[u'ip_address'])


def processIpAddress(ip):
    print("torsocks checking ip " + ip)
    print("torsocks has " + ip + " been checked before? " + str(hasBeenChecked.get(ip, False)))
    if hasBeenChecked.get(ip, False):
        return False
    print("torsocks checking admiral domain")
    if not isAdmiralDomain(ip):
        print("torsocks it's not admiral")
        return False
    print("torsocks it is admiral")
    hasBeenChecked[ip] = True
    for key in getReverseDns(ip)[u'resolutions']:
        processDomain(key[u'domain'])



try:
    print(str(getReverseDns("188.40.75.132")[u'resolutions']))
except:
    exit()
#threadcrowd blocks some tor ips, this is just a simple check of that

#process a list of ips
with open("startingip", rb) as f:
    for line in f:
        processIpAddress(line)

#process a list of domains
with open("startingdomain", "rb") as f:
    for line in f:
        print("torsocks processing " + line)
        processDomain(line)

#process a single domain
#processDomain("hfc195b.com")


pickle.dump( hasBeenChecked, open( "save.p", "wb" ) )
