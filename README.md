#halloffame

keep track of reported vulnerabilities

#Content

- webserver.py : webserver
Can be used to create entries in the JSON file (1 entry per vulnerability) or to test if a vulnerability has been patched.
You need to edit it if you want it to listen on a specific port/interface (default is localhost only)

- hofautoscan.py
Used to perform scan of the entire "database", only the unpatched vulnerability or any vulnerability with a common Incident number (start the program without parameter to see the help)

- hofscanner.py
script performing the check, used by webserver.py and hofautoscan.py

- halloffame.json
JSON file containing the vulnerabilities to check. See inide for crappy examples

- templates
HTML templates for webserver.py


# Needed Python modules
- json
- Flask
- flask_bootstrap
- flask_nav
- dryscrape

see http://dryscrape.readthedocs.io/en/latest/index.html for Dryscrape installation
