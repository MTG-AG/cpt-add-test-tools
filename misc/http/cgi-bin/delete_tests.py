#! /usr/bin/python
import os
import cgi

from constants import constants 

tmpl_file = "../../http_templates/test_list_tmpl.html"

test_results_dir = constants.test_results_dir

def get_files_in_dir(a_dir):
    return [a_dir + "/" + name for name in os.listdir(a_dir)
            if os.path.isfile(os.path.join(a_dir, name))]


arguments = cgi.FieldStorage()
ask_or_del = arguments.getvalue("action")

content = ""
if ask_or_del == "del":
    files = get_files_in_dir(test_results_dir)
    for file in files:
        if file.endswith("__cpt_test_result.xml"):
                os.remove(file)
    content += "<br><br>"
    content = "<p>&nbsp test results deleted</p>"
else:
    content += "<br><br>"
    content += "<p>&nbsp really delete all browser test results? <a href=\"/cgi-bin/delete_tests.py?action=del\">YES, DELETE THEM</a></p>"

                
    
with open(tmpl_file) as f:
    lines = f.readlines()
for line in lines:
    line2 = line.replace('|content|', content)
    print (line2)
