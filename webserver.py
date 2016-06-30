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
reload(sys)
sys.setdefaultencoding('utf-8')
import json
import cgi
import datetime
from flask import Flask
from flask import render_template
from flask import request
from flask import url_for
from flask_bootstrap import Bootstrap
from flask_nav import Nav
from flask_nav.elements import Navbar, View
from hofscanner import checkvuln


########## Navbar
nav = Nav()

@nav.navigation()
def mynavbar():
    return Navbar(
        'Hall of Fame',
        View('All vulnerabilities', 'index'),
        View('Not scanned vulnerabilities', 'display_notscan'),
        View('New vulnerability', 'new_vuln'),
    )
######### End Navbar



## init
json_file='halloffame.json'
app = Flask(__name__)
Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.debug = True
nav.init_app(app)
#app.run(debug=True)
#sorted_halloffame = load_sorted_hof()


##### Index page (hall of Fame)
@app.route('/')
def index():
    return display_hof()

@app.route('/hof')
def display_hof():
    sorted_halloffame = load_sorted_hof()
    return render_template('hof.html', hof_vulns=sorted_halloffame)

##### Vulnerabilities per constituent/reporter/DO ######

@app.route('/constituent/<constituent>')
def display_constituent(constituent):
    sorted_halloffame = load_sorted_hof()
    constituent_halloffame = []

    for i in range (len(sorted_halloffame)):
            if sorted_halloffame[i]["constituent"] == constituent:
                constituent_halloffame.append(sorted_halloffame[i])

    return render_template('hof.html', hof_vulns=constituent_halloffame)

@app.route('/reporter/<reporter>')
def display_reporter(reporter):
    sorted_halloffame = load_sorted_hof()
    reporter_halloffame = []

    for i in range (len(sorted_halloffame)):
            if sorted_halloffame[i]["reporter"] == reporter:
                reporter_halloffame.append(sorted_halloffame[i])

    return render_template('hof.html', hof_vulns=reporter_halloffame)

@app.route('/DO/<dutyoff>')
def display_dutyoff(dutyoff):
    sorted_halloffame = load_sorted_hof()
    dutyoff_halloffame = []

    for i in range (len(sorted_halloffame)):
            if sorted_halloffame[i]["DO"] == dutyoff:
                dutyoff_halloffame.append(sorted_halloffame[i])

    return render_template('hof.html', hof_vulns=dutyoff_halloffame)

@app.route('/notscan/')
def display_notscan():
    sorted_halloffame = load_sorted_hof()
    notscan_halloffame = []

    for i in range (len(sorted_halloffame)):
            if sorted_halloffame[i]["scanable"] == 'no':
                notscan_halloffame.append(sorted_halloffame[i])

    return render_template('hof.html', hof_vulns=notscan_halloffame)

@app.route('/constituent_cleaned/<constituent>')
def display_constituent_cleaned(constituent):
    sorted_halloffame = load_sorted_hof()
    constituent_cleaned_halloffame = []

    for i in range (len(sorted_halloffame)):
            if sorted_halloffame[i]["constituent"] == constituent:
                constituent_cleaned_halloffame.append(sorted_halloffame[i])

    return render_template('hof-clean.html', hof_vulns=constituent_cleaned_halloffame)

#### Modifying JSON file (add) ######
@app.route('/new_vuln/')
def new_vuln():
    return render_template('new_vuln.html')

@app.route('/create_vuln/', methods=['POST'])
def create_vuln():
    halloffame = load_hof()

    last_id = get_last_id()
    new_id = last_id+1

    # creating the new entry
    # data value is buggy for now. Should find a way to receive POST data to build a proper dictionary for data value
    new_vuln = {"DO":request.form['DO'],
        "constituent":request.form['constituent'],
        "reporter":request.form['reporter'],
        "report_date":request.form['report_date'],
        "Incident":request.form['incident_number'],
        "type":request.form['vuln_type'],
        "method":request.form['method'],
        "url":request.form['url'],
        "data":'',
        "check_string":request.form['check_string'],
        "scanable":request.form['scanable'],
        "published":request.form['published'],
        "patched":"no",
        "patched_date":"",
        "last_test":"",
        "id":new_id
    }
    post_data = request.form['post_data']
    if post_data != '':
        data = {}
        for counter in range(1,int(post_data)+1):
            data[request.form['key'+str(counter)]]=request.form['value'+str(counter)]
        new_vuln["data"]=data

    #adding the entry to the list
    halloffame.append(new_vuln)

    #writing on the JSON file
    with open('halloffame.json', 'w') as data:
        data.write(json.dumps(halloffame, indent=4))

    ### if ok, displaying success page
    return view_vuln(new_id)
#    return render_template('done.html')

## function to display/edit all values from a hof entry
#    ## incident_halloffame should be a list a dictionnaries, each dict being a vuln, all will have common incident number
#    return render_template('view_vuln.html', hof_vulns=incident_halloffame)


#@app.route('/view_incident/<incident_number>')
#def view_incident(incident_number):
#    halloffame = load_hof()
#
#    #looking for Incident with the specified Incident Number (should be uniq in the future release)
#    list_incident = []
#    for i in range (len(halloffame)):
#            if halloffame[i]["Incident"] == incident_number:
#                list_incident.append(halloffame[i])
#
#    #list_incident is the list of dictionnaries (based on JSON file)
#    return render_template('view_vuln.html', hof_vulns=list_incident)


@app.route('/view_vuln/<vuln_id>')
def view_vuln(vuln_id):
    halloffame = load_hof()

    #looking for Incident with the specified Incident Number (should be uniq in the future release)
    list_incident = []
    for i in range (len(halloffame)):
            if halloffame[i]["id"] == int(vuln_id):
                list_incident.append(halloffame[i])

    #list_incident is the list of dictionnaries (based on JSON file)
    return render_template('view_vuln.html', hof_vulns=list_incident)


@app.route('/update_vuln/', methods=['POST'])
def update_vuln():
    halloffame = load_hof()

    if request.form['action'] == 'update':
        for i in range (len(halloffame)):
            ## for now url is used as a key - in the future, Incident_number should be uniq
            if int(halloffame[i]["id"]) == int(request.form['id']):
                halloffame[i]["Incident"] = request.form['incident_number']
                halloffame[i]["DO"] = request.form['DO']
                halloffame[i]["constituent"] = request.form['constituent']
                halloffame[i]["reporter"] = request.form['reporter']
                halloffame[i]["report_date"] = request.form['report_date']
                halloffame[i]["type"] = request.form['vuln_type']
                halloffame[i]["method"] = request.form['method']
                halloffame[i]["url"] = request.form['url']
                halloffame[i]["data"] = '' #request.form['data']
                post_data = request.form['post_data']
                if post_data != '':
                    data = {}
                    for counter in range(1,int(post_data)+1):
                        data[request.form['key'+str(counter)]]=request.form['value'+str(counter)]
                        halloffame[i]["data"]=data
                halloffame[i]["check_string"] = request.form['check_string']
                halloffame[i]["scanable"] = request.form['scanable']
                halloffame[i]["published"] = request.form['published']
    elif request.form['action'] == 'test':
        print ('toto')
        for i in range (len(halloffame)):
            ## for now url is used as a key - in the future, Incident_number should be uniq
            if int(halloffame[i]["id"]) == int(request.form['id']):
                halloffame[i] = checkvuln(halloffame[i])
    elif request.form['action'] == 'mark as patched':
        print ('patchouli')
        for i in range (len(halloffame)):
            ## for now url is used as a key - in the future, Incident_number should be uniq
            if int(halloffame[i]["id"]) == int(request.form['id']):
                halloffame[i]["patched"] = 'yes'
                halloffame[i]["patched_date"] = str(datetime.datetime.now())
    elif request.form['action'] == 'mark as unpatched':
        print ('patchouliii')
        for i in range (len(halloffame)):
            ## for now url is used as a key - in the future, Incident_number should be uniq
            if int(halloffame[i]["id"]) == int(request.form['id']):
                halloffame[i]["patched"] = 'no'
                halloffame[i]["patched_date"] = ''
    elif request.form['action'] == 'delete':
        print ('deletion')
        for i in range (len(halloffame)):
            ## for now url is used as a key - in the future, Incident_number should be uniq
            if int(halloffame[i]["id"]) == int(request.form['id']):
                halloffame.pop(i)
                break


    # writing the JSON file
    with open('halloffame.json', 'w') as data:
        data.write(json.dumps(halloffame, indent=4))

    #return render_template('done.html')
    return view_vuln(request.form['id'])



#### Start vulnerability test ####
#### TODO: modify halloffame.py to a python module ####
#@app.route('/test/<incident_number>')
#def test_vuln(incident_number):
#    return ''


############################# dealing with json import ###############
def load_hof():
    with open(json_file, 'r') as data:
        halloffame = json.load(data)
    return halloffame

def load_sorted_hof():
    with open(json_file, 'r') as data:
        halloffame = json.load(data)
    return sorted(halloffame, key=key_is_date, reverse=True)


def key_is_date (dict):
    return dict["report_date"]

############# I now have 2 list of dictionnaries:
############# halloffame : loaded json file
############# sorted_halloffame : loaded json file ordered by report_date

######################## get the bigget id from the json file ###########
def get_last_id():
    halloffame = load_hof()
    seq = [x['id'] for x in halloffame]
    return max(seq)



if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True) #for listening to all interfaces
    #app.run() #for localhost only
