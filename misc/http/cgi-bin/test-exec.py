#! /usr/bin/python
import cgi
import cgitb; cgitb.enable() # Optional; for debugging only
import subprocess
import shlex
from threading import Timer
from config import config

mod_tls_cwd = config.mod_tls_cwd

print "Content-Type: text/html\n\n"
print '<html><head><meta content="text/html; charset=UTF-8" />'
print '<title>test-exec</title><p>'
print '<meta http-equiv="refresh" content="1; URL=https://certpath_test_host:4450">'
print ""

arguments = cgi.FieldStorage()
for i in arguments.keys():
 print arguments[i].value

ocsp_str = ""
if(config.do_use_ocsp_stapling == False):
    ocsp_str = " --no_ocsp_stapl"
 
test_case = arguments.getvalue("test_name")

print "</p></body></html>"
subprocess.Popen("./build/modul_tls tls_server --test_main_dir=" +
        config.cpt_dir_rel_to_mod_tls_cwd + " --test_case=" + test_case + " --port=4450 --result_dir=misc/run/mod_browser_test_results --stay" + ocsp_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=mod_tls_cwd);

