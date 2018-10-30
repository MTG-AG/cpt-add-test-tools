#! /usr/bin/python
import cgi
import cgitb; cgitb.enable() # Optional; for debugging only
import subprocess
import shlex
from threading import Timer
from config import config
import os.path

def write_dyn_port_file(port_int):
    try:
        file = open(config.dyn_srv_port_file, "w")
        port_str = str(port_int)
        file.write(port_str)
        file.close()
    except:
        print 'error when trying to write port number to state file ' + config.dyn_srv_port_file

def read_dyn_port_file():
    try:
        if(not os.path.isfile(config.dyn_srv_port_file)):
            print 'going to write initial dyn_port_file with port nr = ' + str(config.dyn_srv_port_min) + ' file<br>\n'
            write_dyn_port_file(config.dyn_srv_port_min)
            print 'wrote initial dyn_port_file<br>\n'
        port_str = ""
        with open(config.dyn_srv_port_file) as file:  
            port_str = file.read() 
        return int(port_str)
    except ValueError as err:
        print 'Value error during port number conversion: '
        print(err)
        print '<br>\n'
        return config.dyn_srv_port_min
    except Exception as err:
        print 'Exception while reading dynamic port from file: \n'
        print(err)
        print '<br>\n'
    except:
        print 'unknown error while reading dynamic port from file<br>\n'
        return config.dyn_srv_port_min
        

mod_tls_cwd = config.mod_tls_cwd

print "Content-Type: text/html\n\n"
print '<html><head><meta content="text/html; charset=UTF-8" />'
print '<title>test-exec</title><p>'

port = read_dyn_port_file()
port += 1
if(port > config.dyn_srv_port_max):
    port = config.dyn_srv_port_min
write_dyn_port_file(port)

print '<meta http-equiv="refresh" content="1; URL=https://certpath_test_host:'+str(port)+'">'
print ""

arguments = cgi.FieldStorage()
for i in arguments.keys():
 print arguments[i].value

ocsp_str = ""
if(config.do_use_ocsp_stapling == False):
    ocsp_str = " --no_ocsp_stapl"
 
test_case = arguments.getvalue("test_name")

print "</p></body></html>"
subprocess.Popen("./build/modul_tls tls_server --expect_app_data --test_main_dir=" +
        config.cpt_dir_rel_to_mod_tls_cwd + " --test_case=" + test_case + " --port=" + str(port) + " --result_dir=misc/run/mod_browser_test_results --stay" + ocsp_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=mod_tls_cwd);

