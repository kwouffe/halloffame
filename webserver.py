#!/usr/bin/env python
# webserver.py - web app to display/edit halloffame.json

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
from flask_bootstrap import Bootstrap


## json file path
json_file='halloffame.json'

app = Flask(__name__)
Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.debug = True
#app.run(debug=True)
#sorted_halloffame = load_sorted_hof()

@app.route('/')
def index():
    return display_hof()

@app.route('/hof')
def display_hof():
    sorted_halloffame = load_sorted_hof()
    return render_template('hof.html', hof_vulns=sorted_halloffame)

############
### TODO ###
############

#### Modifying JSON file (add/edit) ######
@app.route('/edit/<incident_number>')
def edit_vuln(incident_number):
    return ''

@app.route('/new_vuln/')
def new_vuln():
    return ''


#### Start vulnerability test ####
#### TODO: modify halloffame.py to a python module ####
@app.route('/test/<incident_number>')
def test_vuln(incident_number):
    return ''


############################# dealing with json import ###############
#with open(json_file, 'r') as data:
#    halloffame = json.load(data)

#sorted_halloffame = sorted(halloffame, key=key_is_date, reverse=True)


def load_hof():
    with open(json_file, 'r') as data:
        halloffame = json.load(data)


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
