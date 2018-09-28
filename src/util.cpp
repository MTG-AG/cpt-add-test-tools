/**
 * (C) 2017 cryptosource GmbH
 *
 * The TLS Test Tool is released under the Simplified BSD License (see license.txt)
 */


#include <fstream>
#include <iostream>
#include "util.h"
#include <botan/exceptn.h>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/foreach.hpp>

/* linux only ==> */
#include <sys/types.h>
#include <dirent.h>
/* <== linux only */

using boost::property_tree::ptree;
using namespace std;

namespace {
  template <typename t>
  inline std::string num_to_string(t num)
  {
    std::stringstream ss;
    std::string str_is;
    ss << num;
    ss >> str_is;
    return str_is;
  }

  bool string_ends_with(
    std::string const &fullString,
    std::string const &ending
  )
  {
    if(fullString.length() >= ending.length())
    {
      return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    }
    else
    {
      return false;
    }
  }


std::vector<unsigned char> read_bin_file(std::string const& filename)
{
  std::ifstream file(filename.c_str(), ios::in | ios::binary | ios::ate);
  if(!file.is_open())
  {
    throw Botan::Invalid_Argument("could not open file '" + filename + "'");
  }
  std::ifstream::pos_type size;
  size = file.tellg();
  std::vector<unsigned char> result(size);
  file.seekg(0, ios::beg);
  file.read((char*) (&result[0]), size);
  file.close();
  return result;
}
}

std::vector<std::string> get_entries_of_dir(
  std::string const        & dir_name,
  dir_entry_extract_mode_t extr_mode,
  std::string const        & postfix,
  bool                     get_only_entries_that_are_dirs,
  std::string const        & exclude_postfix,
  std::string const        & prefix
)
{
  std::vector<std::string> result;
  DIR* dir;
  struct dirent* ent;
  if((dir = opendir(dir_name.c_str())) != NULL)
  {
    while((ent = readdir(dir)) != NULL)
    {
      std::string s(ent->d_name);
      //std::cout <<  "checking string = " << s << "\n";
      if(get_only_entries_that_are_dirs && (ent->d_type != DT_DIR))
      {
        continue;
      }
      if(s.find(".") == 0)
      {
        continue;
      }
      if((prefix != "") && s.find(prefix) != 0)
      {
        continue;
      }
      if((postfix != "") && !string_ends_with(s, postfix))
      {
        continue;
      }
      if((exclude_postfix != "") && string_ends_with(s, exclude_postfix))
      {
        continue;
      }
      std::string prefix = "";
      if(extr_mode == dir_entries_with_path)
      {
        prefix = dir_name + "/";
      }
      result.push_back(prefix + s);
    }
    closedir(dir);
  }
  else
  {
    throw Botan::Internal_Error("could not open directory '" + dir_name + "'");
  }
  return result;
} // get_entries_of_dir


std::vector<uint8_t> get_ee_cert_ocsp_response( std::string const& test_cases_dir)
{

  std::vector<std::string> resp_dir_paths = get_entries_of_dir(
      test_cases_dir,
      dir_entries_only_leafs,
      "ocspResponses",
      true
      );
  if(resp_dir_paths.size() != 1)
  {
    std::string found_dirs;
    for(auto s : resp_dir_paths)
    {
      if(found_dirs.size())
      {
        found_dirs += ",";
      }
      found_dirs += s;
    }
    throw Botan::Invalid_Argument("invalid number of 'ocspResponses' directories: expected 1, found " + std::to_string(resp_dir_paths.size()) + ": " + found_dirs);
  }
  std::vector<std::string> ocsp_resp_paths = get_entries_of_dir(
      test_cases_dir + "/ocspResponses",
      dir_entries_with_path,
      "_EE_RESP.ocsp.der",
      false 
      );
  if(ocsp_resp_paths.size() != 1)
  {
    throw Botan::Invalid_Argument("invalid number of '*_EE_RESP.ocsp.der' files: expected 1, found " + std::to_string(ocsp_resp_paths.size()));
  }
  return read_bin_file(ocsp_resp_paths[0]);
}

test_case_info_t get_test_case_info_from_dir(
  std::string const& test_cases_dir,
  std::string const& test_case
)
{
  std::string test_case_dir = test_cases_dir + "/" + test_case;
  std::vector<std::string> key_file_paths = get_entries_of_dir(
    test_case_dir,
    dir_entries_with_path,
    ".TC.pem.key",
    false,
    ".crt.pem"
    );
  if(key_file_paths.size() != 1)
  {
    throw Botan::Invalid_Argument(
            "did find " + num_to_string(
              key_file_paths.size()
            ) + " key files instead of one"
    );
  }
  test_case_info_t result;
  result.server_key_file_path = key_file_paths[0];

  result.server_cert_chain_file_path = test_case_dir + "/paths/" + "issuedTo.pem";
  return result;
}



static cert_path_validation_result_t parse_xml_for_expected_test_result(ptree const& pt)
{
  std::string exp_res = pt.get_child("TestStep").get_child("ExpectedResult").get<std::string>("Text");
  if(exp_res == "VALID" || exp_res == "valid" || exp_res == "Valid")
  {
    return cert_path_validation_result_t::valid;
  }
  else if(exp_res == "INVALID" || exp_res == "invalid" || exp_res == "Invalid")
  {
    return cert_path_validation_result_t::invalid;
  }
  throw Botan::Invalid_Argument("could not parse test result string '" + exp_res + "'");
}

static std::string parse_xml_for_purpose(ptree const& pt)
{
  return pt.get<std::string>("Purpose");
}

static std::string parse_xml_for_severity(ptree const& pt)
{
  std::string result = pt.get_child("TestStep").get<std::string>("Severity");
  if((result != "ERROR") && (result != "WARNING"))
  {
    throw Botan::Invalid_Argument("encountered invalid String for severity: " + result);
  }
  return result;
}

cert_path_test_parameters_t parse_test_case_parameters(
  std::string const& test_specs_dir,
  std::string const& sought_test_case
)
{
  cert_path_test_parameters_t result;

  std::vector<std::string> mod_dirs = get_entries_of_dir(test_specs_dir, dir_entries_with_path, "", true);
  for(std::string const& mod_dir : mod_dirs)
  {
    std::vector<std::string> mod_specs = get_entries_of_dir(mod_dir, dir_entries_with_path, ".xml", false);
    for(std::string const& mod_spec : mod_specs)
    {
      std::ifstream is(mod_spec);
      ptree pt;
      read_xml(is, pt);
      ptree test_case     = pt.get_child("testCase");
      std::string test_id = pt.get<std::string>("testCase.<xmlattr>.id");

      if(test_id == sought_test_case)
      {
        result.m_validation_result = parse_xml_for_expected_test_result(test_case);
        result.m_purpose  = parse_xml_for_purpose(test_case);
        result.m_severity = parse_xml_for_severity(test_case);
        return result;
      }
    }
  }
  throw Botan::Invalid_State(
          "could not find xml test specification for test case '" + sought_test_case + "'" + " in dir '" + test_specs_dir
          + "'"
  );
}

static std::string cert_path_validation_result_to_string(cert_path_validation_result_t cpvr)
{
  if(cpvr == cert_path_validation_result_t::valid)
  {
    return "VALID";
  }
  else if(cpvr == cert_path_validation_result_t::invalid)
  {
    return "INVALID";
  }
  throw Botan::Internal_Error("uncovered value fo cert_path_validation_result_t");
};

void write_test_result_file(
  std::string const                    & output_dir,
  std::string const                    & test_case_name,
  std::string const                    & info_text,
  cert_path_test_parameters_t const*   expected_result,
  cert_path_validation_result_t const* actual_result,
  Botan::TLS::Alert const*             rec_alert
)
{
  std::string filename(output_dir + "/" + test_case_name + "__cpt_test_result.xml");
  ptree tree;
  std::string expect_result_str("--");
  std::string actual_result_str("--");
  if(expected_result)
  {
    expect_result_str = cert_path_validation_result_to_string(expected_result->m_validation_result);
  }
  if(actual_result)
  {
    actual_result_str = cert_path_validation_result_to_string(*actual_result);
  }

  std::string test_result = "inconclusive";
  if(expected_result && actual_result)
  {
    if(expected_result->m_validation_result == *actual_result)
    {
      test_result = "PASS";
    }
    else
    {
      test_result = expected_result->m_severity;
    }
  }
  boost::posix_time::ptime ptime = boost::posix_time::second_clock::local_time();


  std::string alert_desc;
  std::string alert_level;

  if(rec_alert)
  {
    alert_desc  = rec_alert->type_string();
    alert_level = rec_alert->is_fatal() ? "Fatal" : "Warning";
  }

  tree.put("TestCase.Id", test_case_name);

  tree.put("TestCase.ValidationResult.Expected", expect_result_str);
  tree.put("TestCase.ValidationResult.Actual", actual_result_str);
  tree.put("TestCase.Description", expected_result->m_purpose);
  tree.put("TestCase.Severity", expected_result->m_severity);
  tree.put("TestCase.InfoText", info_text);

  tree.put("TestCase.ExecutionTime", to_iso_extended_string(ptime));
  tree.put("TestCase.TestResult", test_result);
  tree.put("TestCase.ReceivedAlert.Description", alert_desc);
  tree.put("TestCase.ReceivedAlert.Level", alert_level);

  boost::property_tree::xml_writer_settings<std::string> settings(' ', 4);
  write_xml(filename, tree, std::locale(), settings);
} // write_test_result_file

void conclude_test_result_and_write_it(
  std::string const                  & output_dir,
  std::string const                  & test_case_name,
  std::string const                  & info_text,
  bool                               handshake_begun,
  bool                               handshake_completed,
  cert_path_test_parameters_t const* expected_result,
  Botan::TLS::Alert const*           rec_alert
)
{
  std::unique_ptr<cert_path_validation_result_t> actual_result;
  if(handshake_begun)
  {
    cert_path_validation_result_t res = cert_path_validation_result_t::invalid;

    /** firefox sends the fatal alert after the completed handshake, thus we
     * cannot solely realy on a completed handshake.
     */
    if(handshake_completed && (!rec_alert || !rec_alert->is_fatal()))
    {
      res = cert_path_validation_result_t::valid;
    }

    actual_result = std::unique_ptr<cert_path_validation_result_t>(new cert_path_validation_result_t(res));
  }
  write_test_result_file(output_dir, test_case_name, info_text, expected_result, actual_result.get(), rec_alert);
}

std::unique_ptr<Botan::TLS::Alert> try_parse_alert(
  uint8_t const* buf,
  uint32_t       got
)
{
  if(got >= 7)
  {
    // may be an unencrypted alert, check the record header:
    if(buf[0] == 21 && buf[1] <= 3 && buf[2] <= 3 && buf[3] == 0 && buf[4] == 2)
    {
      Botan::secure_vector<uint8_t> alert_vec;
      for(unsigned i = 5; i < 7; i++)
      {
        alert_vec.push_back(buf[i]);
      }
      try
      {
        return std::unique_ptr<Botan::TLS::Alert>(new Botan::TLS::Alert(alert_vec));
      }
      catch(...)
      { }
    }
  }
  return std::unique_ptr<Botan::TLS::Alert>();
}
