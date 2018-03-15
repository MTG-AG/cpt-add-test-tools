#! /usr/bin/python
import os
from create_test_result_summary import make_html_table
from config import config
from constants import constants 

tmpl_file = config.template_file 

test_cases_dir = config.test_cases_dir

test_results_dir = constants.test_results_dir 
test_list_content = make_html_table(test_cases_dir, test_results_dir)

with open(tmpl_file) as f:
    lines = f.readlines()
for line in lines:
    line2 = line.replace('|content|', test_list_content)
    print (line2)
