#!/usr/bin/env python
# halloffame.py - automated check for reported vulns (Hall Of Fame)

"""
Check Hall OF Fame vulnerabilities
Use for automation of scan
Author: Emilien LE JAMTEL
CERT-EU - version 1.0
30/05/2016
"""

import sys
import requests
import json
import datetime
from hofscanner import checkvuln


######### Functions calling checkvuln function on selected vulnerability (full, unpatched od incident_number)
def full_scan(hof):
    hof_updated = hof
    for i in range (len(hof)):
        hof_updated[i] = checkvuln(hof[i])
    return hof_updated


def unpatched_scan(hof):
    hof_updated = hof
    for i in range (len(hof)):
            if hof[i]["patched"] == 'no':
                hof_updated[i] = checkvuln(hof[i])
    return hof_updated


## function returning list for specific Incident Number
def incident_scan (hof,incident_number):
    hof_updated = hof
    for i in range (len(hof)):
            if hof[i]["Incident"] == incident_number:
                hof_updated[i] = checkvuln(hof[i])
    return hof_updated

#################################################################################

######## Functions to read/write the halloffame ########

def load_hof(json_file):
    with open(json_file, 'r') as data:
        halloffame = json.load(data)
    return halloffame

def write_hof(hof,json_file):
    with open(json_file, 'w') as data:
        data.write(json.dumps(hof, indent=4))


############### Main ###############

if len(sys.argv) != 3:
    print ('Usage: python halloffame.py [JSON file] [option]')
    print ('options are:')
    print ('fullscan = scan all entries in the halloffame.json file')
    print ('unpatched = scan all unpatched vulnerabilities in the halloffame.json file')
    print ('123456 = scan all vulnerabilities related to incident number 123456')
    sys.exit()

halloffame_json = sys.argv[1]
option = sys.argv[2]

halloffame = load_hof(halloffame_json)

## make a backup
write_hof(halloffame,halloffame_json + '.save')

## based on the option, we will replace the actual halloffame

if str(option) == 'fullscan':
    halloffame_updated = full_scan(halloffame)
elif str(option) == 'unpatched':
    halloffame_updated = unpatched_scan(halloffame)
else:
    halloffame_updated = incident_scan(halloffame,option)


######### Overwriting the json file ###############

write_hof(halloffame_updated,halloffame_json)

###################################################
