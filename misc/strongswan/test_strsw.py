#!/usr/bin/python

from bs4 import BeautifulSoup
from xml.dom import minidom
import xml.etree.ElementTree as ET
import sys
import re
import os
import shutil
import subprocess
from optparse import OptionParser
import time 

class TestCfg:
    strsw_certs_dir = ""
    strsw_cacerts_dir = ""
    strsw_key_dir = ""
    result_output_folder = ""
    test_spec_expected_result = ""
    test_spec_severity = ""
    test_spec_desc = ""
    test_subject_crl_dir = ""
    test_subject_user_at_host = ""
    test_subject_passwd = ""
    test_subject_remote_cmd = ""
    do_exec_crl_tests_exclusively = False
    test_subject_log_file_path = ""

def get_immediate_subdirectories(a_dir):
    return [name for name in os.listdir(a_dir)
        if os.path.isdir(os.path.join(a_dir, name))]

def get_immediate_subdirectory_paths(a_dir):
    return [os.path.join(a_dir, name) for name in os.listdir(a_dir)
        if os.path.isdir(os.path.join(a_dir, name))]

def get_file_paths_in_dir(a_dir):
    return [a_dir + "/" + name for name in os.listdir(a_dir)
        if os.path.isfile(os.path.join(a_dir, name))]

def delete_dir_content(dir):
    files = get_file_paths_in_dir(dir)
    for file in files:
        print "checking file for deletion: " + file
        if((not file.endswith(".crt")) and (not file.endswith(".pem"))):
            continue
        os.remove(file)
        print "deleted file: " + file

def parse_output_for_validation_result(output, test_case_name, output_folder,
        test_cfg, error_string, log_string):
    m = re.search('connection \'(.+)\' established successfully', output)
    m_private_key_error = re.search('no private key found for ', output)
    m_auth_failed = re.search('received AUTHENTICATION_FAILED notify error', output)

    actual_res = ""
    severity = test_cfg.test_spec_severity 
    info_text = ""
    if(m):
        print "cert path validation successful"
        actual_res = "VALID"
    else:
        print "cert path validation unsuccessful"
        if(m_private_key_error):
            actual_res = "internal test error"
            info_text = "private key not found"
        elif(m_auth_failed):
            actual_res = "INVALID"
        else:
            actual_res = "internal test error" 
            info_text = "unknown error during test"
    root = ET.Element("TestCase")
    ET.SubElement(root, "Id").text = test_case_name
    val_res = ET.SubElement(root, "ValidationResult")
    ET.SubElement(val_res, "Expected").text = test_cfg.test_spec_expected_result
    ET.SubElement(val_res, "Actual").text = actual_res
    ET.SubElement(root, "Description").text = test_cfg.test_spec_desc
    ET.SubElement(root, "Severity").text = severity
    ET.SubElement(root, "InfoText").text = info_text
    ET.SubElement(root, "ExecutionTime").text = ""
    print "actual result = " + actual_res + ", expected_result = " + test_cfg.test_spec_expected_result
    if(actual_res.strip() == test_cfg.test_spec_expected_result.strip()):
        ET.SubElement(root, "TestResult").text = "PASS"
    else:
        ET.SubElement(root, "TestResult").text = severity
    if(error_string):
        ET.SubElement(root, "TestResult").text = "test exec error"
        ET.SubElement(root, "InfoText").text = ", test exec error: " + error_string
    alert = ET.SubElement(root, "ReceivedAlert")
    ET.SubElement(alert, "Description").text = ""
    ET.SubElement(alert, "Level").text = ""
    tree = ET.ElementTree(root)
    result_file = output_folder + "/" + test_case_name + "__cpt_test_result.xml"
    result_remote_log_file = output_folder + "/" + test_case_name + "__cpt_test_remote_log.txt"
    print "writing result file = " + result_file
    xmlstr = BeautifulSoup(ET.tostring(root), "xml").prettify()
    with open(result_file, "w") as f:
        f.write(xmlstr)
    if(log_string != ""):
        with open(result_remote_log_file, "w") as f:
            f.write(log_string)

def parse_test_spec(test_spec_file, test_cfg):
    tree = ET.parse(test_spec_file)
    root = tree.getroot()
    for child2 in root:
        if(child2.tag.endswith("Purpose")):
            test_cfg.test_spec_desc = child2.text
            print "Purpose = " + test_cfg.test_spec_desc
        if(child2.tag.endswith("TestStep")):
            for child1 in child2:
                if(child1.tag.endswith("Severity")):
                    test_cfg.test_spec_severity = child1.text
                    print "found severity = " + test_cfg.test_spec_severity
                if(child1.tag.endswith("ExpectedResult")):
                    for child in child1:
                        if(child.tag.endswith("Text")):
                            test_cfg.test_spec_expected_result = child.text
                            print "found expected_result = " + test_cfg.test_spec_expected_result



def get_test_spec_data(test_spec_dir, test_name, test_cfg):
    mod_dirs = get_immediate_subdirectory_paths(test_spec_dir)
    for dir in mod_dirs:
        spec_files = get_file_paths_in_dir(dir)
        for spec_file in spec_files:
            tree = ET.parse(spec_file)
            root = tree.getroot()
            if(root.get("id") == test_name):
                print "found the correct test spec"
                parse_test_spec(spec_file, test_cfg)
                return

def get_leaf_robust(path):
    purified_path = path
    while(purified_path.endswith("/")):
            purified_path = purified_path[:-1]
    return os.path.basename(purified_path)

def set_remote_crls(user_at_host, remote_crl_path, crl_src_dir):
    result = ""
    sshpass_prefix = "sshpass -p" + test_cfg.test_subject_passwd + " "
    del_crl_cmd = sshpass_prefix + "ssh " + user_at_host + " 'find " + remote_crl_path + " -name \"*.pem.crl\" | xargs -n1 rm'"
    print "del_crl_cmd=" + del_crl_cmd
    p = subprocess.Popen(del_crl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    p.wait()
    if(p.returncode != 0):
        result += " Error during crl deletion: stdout = " + str(out) + ", stderr = " + str(err)
        print result
    crl_files = get_file_paths_in_dir(crl_src_dir)
    for crl_file in crl_files:
        if(crl_file.endswith(".pem.crl")):
            cp_crl_cmd= sshpass_prefix + "scp -o StrictHostKeyChecking=no " + crl_file + " " + user_at_host + ":" + remote_crl_path
            print "scp_cmd=" + cp_crl_cmd
            p2 = subprocess.Popen(cp_crl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p2.communicate()
            p2.wait()
            if(p2.returncode != 0):
                result += ", Error during crl copying: stdout = " + str(out) + ", stderr = " + str(err)
                print result
 
    return result

def exec_remote_cmd(test_cfg, remote_cmd):
    sshpass_prefix = "sshpass -p" + test_cfg.test_subject_passwd + " "
    custom_cmd = sshpass_prefix + " ssh " + test_cfg.test_subject_user_at_host + " '" + remote_cmd + "'"
    print "executing custom_cmd = " + custom_cmd
    p = subprocess.Popen(custom_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
    out, err = p.communicate()
    p.wait()
    return out, err


def exec_test(test_case_path, test_cfg):
    error_string = ""
    subdirs = get_immediate_subdirectory_paths(test_case_path)
    is_crl_test = False
    crl_dir = ""
    for subdir in subdirs:
        if(subdir.endswith("/crls")):
            is_crl_test = True
            crl_dir = subdir
            break
    if is_crl_test and test_cfg.do_exec_crl_tests_exclusively:
        if test_cfg.test_subject_crl_dir != "":
            error_string += set_remote_crls(test_cfg.test_subject_user_at_host,
                    test_cfg.test_subject_crl_dir,
                    crl_dir)
    elif ((not is_crl_test) and (not test_cfg.do_exec_crl_tests_exclusively)):
        # nothing to do
        print "executing non-crl test"
    else:
        print "skipping test (is_crl_test = " + str(is_crl_test) + ")"
        return
    if(test_cfg.test_subject_log_file_path):
        exec_remote_cmd(test_cfg, "truncate -s 0 " + test_cfg.test_subject_log_file_path)
    if(test_cfg.test_subject_remote_cmd != ""):
        exec_remote_cmd(test_cfg, test_cfg.test_subject_remote_cmd)

    print "executing test: " + test_case_path
    delete_dir_content(test_cfg.strsw_certs_dir) 
    delete_dir_content(test_cfg.strsw_cacerts_dir) 
    delete_dir_content(test_cfg.strsw_key_dir) 
    files = get_file_paths_in_dir(test_case_path)
    for file in files:
        print "file = " + file
        if file.endswith(".TC.pem.crt"):
            shutil.copyfile(file, test_cfg.strsw_certs_dir + "/ee.crt.pem")
        elif file.endswith(".CA.pem.crt"):
            shutil.copy(file, test_cfg.strsw_cacerts_dir)
        elif file.endswith(".TA.pem.crt"):
            shutil.copy(file, test_cfg.strsw_cacerts_dir)
        elif file.endswith(".TC.pem.key"):
            shutil.copyfile(file, test_cfg.strsw_key_dir+ "/key.pem")
    print "restarting ipsec"
    p = subprocess.Popen("ipsec restart", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
    p.wait()
    if(p.returncode != 0):
       error_string += "error during 'ipsec restart'" 
    time.sleep(3)
    print "starting connection attempt"
    p = subprocess.Popen("ipsec up trap-any", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
    out, err = p.communicate()
    p.wait()
    if(p.returncode != 0):
       error_string += "error during 'ipsec up trap-any'" 
    time.sleep(1)
    test_name = get_leaf_robust(test_case_path)

    p = subprocess.Popen("ipsec stop", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
    p.wait()
    info_string = ""
    if(test_cfg.test_subject_log_file_path):
        out2, err2 = exec_remote_cmd(test_cfg, "cat " + test_cfg.test_subject_log_file_path)
        info_string += "log = ====\n" + str(out2) + "\n===="
    print "leaf of '" + test_case_path + "' is '" + test_name + "'"
    parse_output_for_validation_result( str(out), test_name,
        test_cfg.result_output_folder, test_cfg, error_string, info_string)
    print "stdout = " + str(out)
    print " << end of stdout >> "
    print "\nstderr = " + str(err)
    print " << end of stderr >> "

parser = OptionParser()

parser.add_option("-t", "--test_case", dest="test_case_path", 
        help="directory containing a single test case to execute", metavar = "TEST_CASE_DIR")

parser.add_option("-T", "--test_case_dir", dest="test_cases_dir", 
        help="directory containing all the test cases to execute as subdirs",
        metavar = "TEST_CASES_DIR")

parser.add_option("-o", "--output_strsw_cfg_dir", dest="output_strsw_cfg_dir",
        help = "[mandatory] directory in which the strongSwan certificate subdirectories are found (i.e. typically /etc/ipsec.d)", 
        metavar = "DIR")

parser.add_option("-r", "--result_output_folder", dest="result_output_folder",
        help = "[mandatory] directory into which to write the test results", metavar =
        "DIR")

parser.add_option("-s", "--test_case_spec_dir", dest="test_case_spec_dir",
        help = "[mandatory] directory which contains the test case specification, i.e. the"
        " 'testcases' directory of the cpt", metavar = "DIR")

parser.add_option("-c", "--remote_crl_dir", dest="remote_crl_dir", help =
        "absolute directory path of the tested application's CRL directory on the remote test system", 
        metavar = "REMOTE_DIR")

parser.add_option("-l", "--login", dest="remote_user_at_host", 
        help = "ssh login in the form <user>@<host> for the remote system on which the tested application is running", 
        metavar = "<USER>@<HOST>")

parser.add_option("-p", "--passwd", dest="remote_user_passwd", 
        help = "ssh login password for the remote machine on which the tested application is running", 
        metavar = "PASSWORD")

parser.add_option("-e", "--exec_remote", dest="remote_exec_cmd", 
        help = "command which is executed on the remote test subject machine"
        " after the test setup and can for instance be used to (re)start"
        " the application under test", metavar = "REMOTE_COMMAND")

parser.add_option("-d", "--do_exec_crl_tests", 
        action = "store_true",
        dest="do_exec_crl_tests",
        default = False, 
        help = "if this flag is specified, the CRL tests (i.e. those having a "
        "subdirectory 'crls') are executed, otherwise only the non-CRL tests are executed")

parser.add_option("-f", "--remote_log_file", dest="remote_log_file", 
        help = "path to the test subject's log file on the remote machine. if "
        "this option is specified, the remote log file is deleted prior to each "
        "test execution and its content after test execution is set in the test "
        "result", metavar="REMOTE_DIR")
        
(options, args) = parser.parse_args()
if options.test_case_path and options.test_cases_dir:
    parser.error("too many arguments")
if (not options.test_case_path) and (not options.test_cases_dir):
    parser.error("missing test case (collection or single) specification")
if not options.output_strsw_cfg_dir:
    parser.error("missing output_strsw_cfg_dir specification")
if not options.result_output_folder:
    parser.error("missing result_output_folder specification")
if not options.test_case_spec_dir:
    parser.error("missing test_case_spec_dir specification")

test_cfg = TestCfg()

if(options.remote_user_passwd):
    test_cfg.test_subject_passwd = options.remote_user_passwd
if(options.remote_user_at_host):
    test_cfg.test_subject_user_at_host = options.remote_user_at_host

if(options.remote_log_file):
    if(not options.remote_user_at_host) or (not options.remote_user_passwd):
        parser.error("if --remote_log_file is used, both --user_at_host and --passwd must be specified")
    test_cfg.test_subject_log_file_path = options.remote_log_file

if(options.remote_exec_cmd):
    if(not options.remote_user_at_host) or (not options.remote_user_passwd):
        parser.error("if --exec_remote is used, both --user_at_host and --passwd must be specified")
    test_cfg.test_subject_remote_cmd = options.remote_exec_cmd

if options.remote_crl_dir: 
    if (not options.remote_user_at_host) or (not options.remote_user_passwd):
        parser.error("if --remote_crl_dir is used, both --user_at_host and --passwd must be specified")
    test_cfg.test_subject_crl_dir = options.remote_crl_dir


if options.do_exec_crl_tests:
    test_cfg.do_exec_crl_tests_exclusively = True

test_cfg.strsw_certs_dir     = options.output_strsw_cfg_dir + "/certs"
test_cfg.strsw_cacerts_dir   = options.output_strsw_cfg_dir + "/cacerts"
test_cfg.strsw_key_dir       = options.output_strsw_cfg_dir + "/private"
test_cfg.result_output_folder = options.result_output_folder

if(options.test_cases_dir):
    test_list = get_immediate_subdirectories(options.test_cases_dir)
    for test_case in test_list:
        get_test_spec_data(options.test_case_spec_dir, test_case, test_cfg)
        exec_test(options.test_cases_dir + "/" + test_case, test_cfg)
else:
    get_test_spec_data(options.test_case_spec_dir, get_leaf_robust(options.test_case_path), test_cfg)
    exec_test(options.test_case_path, test_cfg)
