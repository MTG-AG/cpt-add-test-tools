#! /usr/bin/python
import sys
import os
import subprocess
import shutil

def get_immediate_subdirectories(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def get_file_names_in_dir(a_dir):
    return [ name for name in os.listdir(a_dir)
            if os.path.isfile(os.path.join(a_dir, name))]

def get_file_paths_in_dir(a_dir):
    return [a_dir + "/" + name for name in os.listdir(a_dir)
            if os.path.isfile(os.path.join(a_dir, name))]

def delete_crl_files_in_dir(dir):
    files = get_file_paths_in_dir(dir)
    for file in files:
        if file.endswith(".crl"):
                os.remove(file)

def has_test_case_crl_dir(cpt_main_dir, test_name):
    subdirs = get_immediate_subdirectories(cpt_main_dir + "/output/" + test_name)
    return "crls" in subdirs


run_crl_tests = False
crl_folder = ""

if(len(sys.argv) == 5):
    print "tests without CRL tests"
elif(len(sys.argv) == 7):
    ca_files_dir = sys.argv[5]
    crl_folder = sys.argv[6]
    print "tests with CRL tests, crl_folder = " + crl_folder
    run_crl_tests = True
else:
    print "len(sys.argv) = " + str(len(sys.argv))
    print "usage (non-CRL-test mode): " + sys.argv[0] + " 'cpt directory' 'output directory' 'hostname' 'port'"
    print "usage (CRL-test mode):     " + sys.argv[0] + " 'cpt directory' 'output directory' 'hostname' 'port' ''ca certs output dir 'crl ouput dir'"
    sys.exit(1)

cpt_dir = sys.argv[1]
output_dir = sys.argv[2]
hostname = sys.argv[3]
port = sys.argv[4]
test_cases_dir = cpt_dir + "/" + "output"
tests_list = get_immediate_subdirectories(test_cases_dir)
tests_list = sorted(tests_list)

for test_case in tests_list:
    if(has_test_case_crl_dir(cpt_dir, test_case)):
        if(not run_crl_tests):
            continue
        else:
            delete_crl_files_in_dir(crl_folder)
            ca_files = get_file_paths_in_dir(cpt_dir + "/output/" + test_case)

            rm_cmd = "rm " + ca_files_dir + "/*.pem.crt && rm "+ ca_files_dir + "/*.r && rm " + ca_files_dir + "/*.0 && rm " + ca_files_dir + "/*.1"
            p = subprocess.Popen(rm_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
            p.wait()

            for ca in ca_files:
                if(ca.endswith("TA.pem.crt") or ca.endswith("CA.pem.crt")):
                    pass
                else:
                    continue
            

                ca_folder = ca_files_dir
                shutil.copy(ca, ca_folder)

                new_ca_path = ca_folder+"/"+ca.split('/')[-1]
            ca_symlink_cmd = "sudo c_rehash " + ca_files_dir + "/" 
            p = subprocess.Popen(ca_symlink_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
            p.wait()

            crl_files = get_file_paths_in_dir(cpt_dir + "/output/" + test_case + "/crls")
            for crl in crl_files:
                if(not crl.endswith(".pem.crl")):
                        continue
                new_crl_path = crl_folder+"/"+crl.split('/')[-1]
                print("copying {0} to {1}\n".format(crl, new_crl_path))
                shutil.copy(crl, crl_folder)
                rm_cmd = "rm " + crl_folder + "/*.r*"
                p = subprocess.Popen(rm_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
                p.wait()


                if "ROOT" in crl.split('/')[-1]:
                    pass
            crl_symlink_cmd = "sudo c_rehash " + crl_folder + "/" 
            p = subprocess.Popen(crl_symlink_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
            p.wait()

            rights_cmd = "sudo chmod -R 777 " + ca_files_dir 
            p = subprocess.Popen(rights_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
            p.wait()
            
            rights_cmd = "sudo chmod -R 777 " + crl_folder
            p = subprocess.Popen(rights_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
            p.wait()

            restart_cmd = "sudo apache2ctl restart"
            p = subprocess.Popen(restart_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
            p.wait()
                
                
    else:
        if(run_crl_tests):
            continue

    cmd = "./build/modul_tls tls_client " + hostname + " --test_main_dir=" + cpt_dir + " --test_case=" + test_case + " --port=" + port + " --result_dir=" + output_dir
    print cmd
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT);
    p.wait()

    
