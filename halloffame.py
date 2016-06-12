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
import json
import datetime


######### Function returning lists to provide to checkmybooty() function #########
## function returning list of index in halloffame.json -- full scan
def full_scan ():
    return list(range(len(halloffame)))


## function returning list of index in halloffame.json marked as unpatched
def unpatched_scan():
    list_unpatched = []
    for i in range (len(halloffame)):
            if halloffame[i]["patched"] == 'no':
                #print ('index: ' + str(i))
                list_unpatched.append(i)
    return list_unpatched


## function returning list of index in halloffame.json for specific RTIR code
def incident_scan (incident_number):
    list_incident = []
    for i in range (len(halloffame)):
            if int(halloffame[i]["Incident"]) == int(incident_number):
                list_incident.append(i)
    return list_incident

#################################################################################

## function checking the stuffs and modifing the json file
## take a list of index (in the json file) as input (from the *_scan() functions)
def checkmybooty (index_list):
    if len(index_list) == 0:
        print ('fuck it, empty list')
        sys.exit()
    for i in range(len(index_list)):
        ########### printing the vuln details
        print('---------- ' + str(i) +' ---------')
        print('contituent: ' + halloffame[index_list[i]]["constituent"])
        print('RTIR incident number: ' + halloffame[index_list[i]]["Incident"])
        print('Vulnerability: ' + halloffame[index_list[i]]["type"])
        print('URL: ' + halloffame[index_list[i]]["url"])
        
        ########### We want to keep track of some reported vulnerabilities but we have no way to automatically check - so flag "scanable" is set as NO in the JSON file
        if halloffame[index_list[i]]["scanable"] == 'no':
            check_result = 'not scanable'
        else:
            halloffame[index_list[i]]["last_test"] = str(today)
            check_result = check_patched(halloffame[index_list[i]]["method"],halloffame[index_list[i]]["url"],halloffame[index_list[i]]["data"],halloffame[index_list[i]]["check_string"])
        if  check_result[0] == 'YES, it is patched, hell yeah':
            halloffame[index_list[i]]["patched"] = 'yes'
            print('Patched: YES')
            print ('return code: ' + str(check_result[1]))
            if halloffame[index_list[i]]["patched_date"] == '':
                halloffame[index_list[i]]["patched_date"] = str(today)
        elif check_result[0] == 'NO ... still vulnerable':
            halloffame[index_list[i]]["patched"] = 'no'
            print('Patched: NO')
            print ('return code: ' + str(check_result[1]))
        elif check_result[0] == 'fuck it did not worked':
            print ('RTIR incident number: ' + halloffame[index_list[i]]["Incident"])
            print ('Check_string: ' + halloffame[index_list[i]]["check_string"])
            print ('return code: ' + str(check_result[1]))
        elif check_result == 'not scanable':
            print ('No automated scan available')


## function doing the basic check, take values from the halloffame.json file as input
## called by checkmybooty() function
## return a list (result,HTTP return code)
def check_patched(method,url,data,check_string):
    page = requests.request(method, url, data=data, allow_redirects=False)
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


#toto = unpatched_scan()
#toto = full_scan()
#toto = Incident_scan(24096)

#checkmybooty(toto)


if len(sys.argv) != 2:
    print ('Usage: python halloffame.py [option]')
    print ('options are:')
    print ('fullscan = scan all entries in the halloffame.json file')
    print ('unpatched = scan all unpatched vulnerabilities in the halloffame.json file')
    print ('123456 = scan all vulnerabilities related to incident number 123456')
    sys.exit()

option = sys.argv[1]

with open('halloffame.json', 'r') as data:
    halloffame = json.load(data)

today = datetime.date.today()


if str(option) == 'fullscan':
    checkmybooty(full_scan())
elif str(option) == 'unpatched':
    checkmybooty(unpatched_scan())
elif option.isdigit():
    checkmybooty(incident_scan(int(option)))
else:
    print ('RTFM')
    sys.exit()


with open('halloffame.json', 'w') as data:
    data.write(json.dumps(halloffame, indent=4))
