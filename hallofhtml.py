#!/usr/bin/env python
# halloffame.py - automated check for reported vulns (Hall Of Fame)

"""
Generate the Hall Of Fame HTML page
Author: Emilien LE JAMTEL
CERT-EU - version 1.0
30/05/2016
"""

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import json
import cgi
import datetime

def key_is_date (dict):
    return dict["report_date"]

html_last_update = datetime.datetime.now()


if len(sys.argv) != 3:
    print ('Usage: python hallofhtml.py json_file html_page')
    sys.exit()

json_file = sys.argv[1]
html_page = sys.argv[2]

with open(json_file, 'r') as data:
    halloffame = json.load(data)

#### settings ####
html_table = '<head><link rel="stylesheet" type="text/css" href="style.css"></head><body><div>'

html_table = html_table + '<table><tr><th>report date</th><th>reporter</th><th>constituent</th><th>Type</th><th class="poc">PoC</th><th>Incident Number</th><th>DO</th><th>patched</th><th>published</th></tr>'
sorted_halloffame = sorted(halloffame, key=key_is_date, reverse=True)
for i in range(len(sorted_halloffame)):
    #print (halloffame[i]["report_date"])
    new_line = '<tr>'
    new_line = new_line + '<td>' + sorted_halloffame[i]["report_date"] + '</td>' #adding report date
    new_line = new_line + '<td>'  + cgi.escape(sorted_halloffame[i]["reporter"]) + '</td>' #adding reporter nale and address
    new_line = new_line + '<td>' + sorted_halloffame[i]["constituent"] + '</td>' #adding impacted constituent
    new_line = new_line + '<td>' + sorted_halloffame[i]["type"] + '</td>' #adding vulnerability type
    new_line = new_line + '<td class="poc">' + cgi.escape(sorted_halloffame[i]["url"]) + '</td>' #adding URL (PoC)
    new_line = new_line + '<td>' + sorted_halloffame[i]["Incident"] + '</td>' #adding Incident number
    new_line = new_line + '<td>' + sorted_halloffame[i]["DO"] + '</td>' #adding Duty Officer managing this case
    if sorted_halloffame[i]["patched"] == 'no':
        new_line = new_line + '<td class="patch_no">' + sorted_halloffame[i]["patched"] + '</td>' #adding patch status + date (NO)
    else:
        new_line = new_line + '<td td class="patch_yes">' + sorted_halloffame[i]["patched"] + ' ' + sorted_halloffame[i]["patched_date"] + '</td>' #adding patch status + date (YES)
    if sorted_halloffame[i]["published"] == 'no':
        new_line = new_line + '<td class="published_no">' + sorted_halloffame[i]["published"] + '</td>' #adding publish status
    else:
        new_line = new_line + '<td class="published_yes">' + sorted_halloffame[i]["published"] + '</td>' #adding publish status
    new_line = new_line +'</tr>'
    ## concat
    html_table = html_table + new_line

html_table = html_table + '</table></div></body> Last Update: ' + str(html_last_update)

with open(html_page, 'w') as data:
    data.write(html_table)
    data.close()
