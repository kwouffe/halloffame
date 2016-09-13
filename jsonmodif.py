#!/usr/bin/env python
# webserver.py - web app to display/edit halloffame.json
# should be able to launch the vulnerability checking

"""
Web app to display/edit the halloffame.json file
Author: Emilien LE JAMTEL
CERT-EU - version 1.0
30/05/2016
"""

import sys
import json
import cgi

with open('halloffame.json', 'r') as data:
    halloffame = json.load(data)

for i in range (len(halloffame)):
    halloffame[i]["test_type"] = 'request'

with open('halloffame.json', 'w') as data:
    data.write(json.dumps(halloffame, indent=4))
