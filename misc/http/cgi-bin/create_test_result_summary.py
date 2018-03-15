#! /usr/bin/python
import os, sys
import xml.etree.ElementTree as ET
from config import config
from constants import constants 

def get_immediate_subdirectories(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def get_files_in_dir(a_dir):
    return [a_dir + "/" + name for name in os.listdir(a_dir)
            if os.path.isfile(os.path.join(a_dir, name))]

def create_table_entries(test_list, nb_cols):
    rows = [ ]
    for test in test_list:
        column = []
        #column.append("<b><a href=\"test-exec.py?test_name=" + test + "\">" + test + "</b>")
        column.append(test)
        #print test
        for i in  range (1, nb_cols):
            column.append(" ")
        rows.append(column)
    return rows
    

class TestResult:
    id = ""
    test_result = ""
    expected_result = ""
    actual_result = ""
    info_text = ""
    exec_time = ""
    rec_alert_desc = ""
    rec_alert_level = ""
    test_description = ""

def get_test_results_list(test_results_dir):
    file_list = get_files_in_dir(test_results_dir)
    results = []
    for file in file_list:
        result = TestResult()
        tree = ET.parse(file)
        root = tree.getroot()
        result.id = root.find('Id').text.strip()
        result.expected_result = root.find('ValidationResult').find('Expected').text
        result.actual_result = root.find('ValidationResult').find('Actual').text
        result.exec_time = root.find('ExecutionTime').text
        result.info_text = root.find('InfoText').text
        result.rec_alert_desc = root.find('ReceivedAlert').find('Description').text
        result.rec_alert_level = root.find('ReceivedAlert').find('Level').text
        result.test_result = root.find('TestResult').text
        result.test_description = root.find('Description').text
        results.append(result)

    return results

def populate_test_table(test_table, test_results_list, is_html, nb_cols, is_browser):
    for row in test_table:
        test_name = row[0]
        if is_html:
            row[0] = "<b><a href=\"test-exec.py?test_name=" + test_name + "\">" + test_name + "</b>"
        for result in test_results_list:
            if(result.id == test_name):
                row[1] = result.test_result
                if is_html:
                    if result.test_result == "ERROR":
                        row[1] = "<font color=\"red\">ERROR</font>"
                    if result.test_result == "WARNING":
                        row[1] = "<font color=\"orange\">WARNING</font>"
                    if result.test_result == "PASS":
                        row[1] = "<font color=\"green\">PASS</font>"
                row[2] = result.expected_result
                row[3] = result.actual_result
                row[4] = result.rec_alert_desc
                if(is_html):
                    row[5] = result.rec_alert_level
                    row[6] = result.info_text
                    row[7] = result.test_description
                    row[8] = result.exec_time
                else:
                    row[5] = "" # to be filled by tester manually
                    if(is_browser):
                        row[6] = ""
                        row[7] = result.test_description
                    else:
                        row[6] = result.test_description
            for x in range (1 , nb_cols):
                if row[x] is None:
                    row[x] = ""
   
table_hdr_html = [
["name", "Test Name"], [ "result", "Test Result"], [ "exp_val_res", "Expected Validation Result"],
[ "act_val_res", "Actual Validation Result"], ["alert_type", "TLS Alert Type"],
[ "alert_level", "TLS Alert Level"], [ "info", "Info Text"],
[ "descr", "Test Case Description"],  [ "time", "Execution Time"] ]


table_hdr_oo = ["Test",  "Testergebnis",  "Erwartetes Ergebnis" ,
 "Tatsaechliches Ergebnis", "TLS Alert", "Validierungsfehler", 
 "Testbeschreibung" ]

table_hdr_oo_browser = ["Test",  "Testergebnis",  "Erwartetes Ergebnis" ,
 "Tatsaechliches Ergebnis", "TLS Alert", "Validierungsfehler", "Add Exception",
 "Testbeschreibung" ]

def format_table_oo(raw_table, table_hdr):
    result = "|"
    for x in table_hdr:
        result += x + "|"
    result += "\n"
    for row in raw_table:
        result += "|"
        for col in row:
            result += col.strip() + "|"
        result += "\n"
    return result


def format_table_html(raw_table):
    result = ""
    result += '<table> <thead>\n'
    result += "\n<tr>"
    for x in  table_hdr_html:
        result += '\n    <th class="' + x[0] + '">' + x[1] + "</th>"
    result += "\n </tr>\n </thead> \n <tbody>"
    for row in raw_table:
        result += "\n  <tr>"
        for col in row:
            result += "\n    <td>" + col + "</td>"
        result += "\n  </tr>"
    result += "\n</tbody>\n </table>"
    return result

def make_oo_table(test_cases_dir, test_results_dir, is_browser):
    nb_oo_cols = len( table_hdr_oo)
    if(is_browser):
        nb_oo_cols += 1

    try:
        test_list = get_immediate_subdirectories(test_cases_dir)
    except OSError:
        return "could not open test cases directory '" + test_cases_dir + "'"

    test_list = sorted(test_list)

    table_with_first_col_set = create_table_entries(test_list, nb_oo_cols)

    test_results_list = get_test_results_list(test_results_dir)

    #print "table = " +  table_with_first_col_set

    populate_test_table(table_with_first_col_set, test_results_list, is_html =
            False, nb_cols = nb_oo_cols, is_browser = is_browser)
    if(is_browser):
        return format_table_oo(table_with_first_col_set, table_hdr_oo_browser )
    else:
        return format_table_oo(table_with_first_col_set, table_hdr_oo)

def make_html_table(test_cases_dir, test_results_dir):
    nb_html_cols = 9
    try:
        test_list = get_immediate_subdirectories(test_cases_dir)
    except OSError:
        return "<br><br>&nbsp;  could not open test cases directory '" + test_cases_dir + "'"

    test_list = sorted(test_list)

    table_with_first_col_set = create_table_entries(test_list, nb_html_cols)

    test_results_list = get_test_results_list(test_results_dir)

    #print "table = " +  table_with_first_col_set

    populate_test_table(table_with_first_col_set, test_results_list, is_html =
            True, nb_cols = nb_html_cols, is_browser = False)

    return format_table_html(table_with_first_col_set)


#the_test_results_dir = "../../run/mod_browser_test_results" 
is_browser = False

the_test_results_dir = constants.test_results_dir

#test_cases_dir = "../../../../third_party_libs/certification_path_tool/output"
test_cases_dir = config.test_cases_dir
if(len(sys.argv) >= 3):
    if(sys.argv[2] == "browser"):
        is_browser = True
    else:
        raise Exception('invalid value for 2nd argument: must be browser or left out')
if(len(sys.argv) > 1 and sys.argv[1] == "oo"):
    print make_oo_table(test_cases_dir, the_test_results_dir, is_browser)
#elif:
    #print make_html_table(test_cases_dir, the_test_results_dir)
