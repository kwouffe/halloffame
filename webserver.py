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


########## Navbar
nav = Nav()

@nav.navigation()
def mynavbar():
    return Navbar(
        'Hall of Fame',
        View('All vulnerabilities', 'index'),
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

#### Modifying JSON file (add) ######
@app.route('/new_vuln/')
def new_vuln():
    return render_template('new_vuln.html')

@app.route('/create_vuln/', methods=['POST'])
def create_vuln():
    halloffame = load_hof()

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
        "last_test":""
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
    return render_template('done.html')

## function to display/edit all values from a hof entry
#    ## incident_halloffame should be a list a dictionnaries, each dict being a vuln, all will have common incident number
#    return render_template('view_vuln.html', hof_vulns=incident_halloffame)


@app.route('/view_vuln/<incident_number>')
def view_vuln(incident_number):
    halloffame = load_hof()

    #looking for Incident with the specified Incident Number (should be uniq in the future release)
    list_incident = []
    for i in range (len(halloffame)):
            if int(halloffame[i]["Incident"]) == int(incident_number):
                list_incident.append(halloffame[i])

    #list_incident is the list of dictionnaries (based on JSON file)
    return render_template('view_vuln.html', hof_vulns=list_incident)


@app.route('/update_vuln/', methods=['POST'])
def update_vuln():
    halloffame = load_hof()

    print (request.form['reporter'])

    for i in range (len(halloffame)):
        ## for now url is used as a key - in the future, Incident_number should be uniq
        if int(halloffame[i]["Incident"]) == int(request.form['incident_number']) and str(halloffame[i]["url"]) == str(request.form['url']):
            halloffame[i]["DO"] = request.form['DO']
            halloffame[i]["constituent"] = request.form['constituent']
            halloffame[i]["reporter"] = request.form['reporter']
            halloffame[i]["report_date"] = request.form['report_date']
            halloffame[i]["type"] = request.form['vuln_type']
            halloffame[i]["method"] = request.form['method']
            halloffame[i]["url"] = request.form['url']
            halloffame[i]["data"] = request.form['data']
            halloffame[i]["check_string"] = request.form['check_string']
            halloffame[i]["scanable"] = request.form['scanable']
            halloffame[i]["published"] = request.form['published']

    # writing the JSON file
    with open('halloffame.json', 'w') as data:
        data.write(json.dumps(halloffame, indent=4))

    return render_template('done.html')


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


if __name__ == '__main__':
    app.run()
