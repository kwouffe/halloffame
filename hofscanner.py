#!/usr/bin/env python
# halloffame.py - automated check for reported vulns (Hall Of Fame)

"""
Check Hall OF Fame vulnerabilities
Author: Emilien LE JAMTEL
CERT-EU - version 1.0
30/05/2016
"""

import sys
import requests
import datetime

#################################################################################

## function performing the checking - take a dictionnary as entry ##
def checkvuln (vulnerability):
    now = datetime.datetime.now()
    ########### We want to keep track of some reported vulnerabilities but we have no way to automatically check - so flag "scanable" is set as NO in the JSON file
    if vulnerability["scanable"] == 'no':
        check_result = 'not scanable'
        print ('scanable: ' + vulnerability["scanable"])
    else:
        vulnerability["last_test"] = str(now)
        print ('method: ' + vulnerability["method"])
        print ('url :' + vulnerability["url"])
        print ('')
        print ('check_string: ' + vulnerability["check_string"])
        check_result = check_patched(vulnerability["method"],vulnerability["url"],vulnerability["data"],vulnerability["check_string"])
    if  check_result[0] == 'YES, it is patched, hell yeah':
        print ('patched' + str(check_result[1]))
        vulnerability["patched"] = 'yes'
        vulnerability["test_status"] = str(check_result[1])
        if vulnerability["patched_date"] == '':
            vulnerability["patched_date"] = str(now)
    elif check_result[0] == 'NO ... still vulnerable':
        print ('not patched' + str(check_result[1]))
        vulnerability["patched"] = 'no'
        vulnerability["test_status"] = str(check_result[1])
        vulnerability["patched_date"] = ''
    elif check_result[0] == 'fuck it did not worked':
        vulnerability["test_status"] = str(check_result[1])
    elif check_result == 'not scanable':
        print ('No automated scan available')
        vulnerability["test_status"] = '000'
    print (vulnerability["patched"])
    return vulnerability

#################################################################################

## function doing the basic check, take values from the dictionnary file as input
## called by checkmybooty() function
## return a list (result,HTTP return code)
def check_patched(method,url,data,check_string):
    page = requests.request(method, url, data=data, stream=False)
    #print page.text
    if page.status_code != 403:
        if check_string in page.text:
            return ['NO ... still vulnerable',page.status_code]
        else:
            return ['YES, it is patched, hell yeah',page.status_code]
    else:
        #print ('status_code = ' + str(page.status_code))
        return ['fuck it did not worked',page.status_code]

#################################################################################
