#ifndef __util__H_
#define __util__H_

#include <vector>
#include <string>

#include "botan/tls_alert.h"
#include "botan/exceptn.h"

struct timeout_exception_t : public Botan::Exception
{
  timeout_exception_t(const std::string& err = "") : Botan::Exception(err){ }
};
struct connection_exception_t : public Botan::Exception
{
  connection_exception_t(const std::string& err = "") : Botan::Exception(err){ }
};

typedef enum { dir_entries_with_path, dir_entries_only_leafs } dir_entry_extract_mode_t;

enum class cert_path_validation_result_t { valid, invalid };

struct cert_path_test_parameters_t
{
  cert_path_validation_result_t m_validation_result;
  std::string                   m_purpose;
  std::string                   m_severity;
};

struct test_case_info_t
{
  std::string server_cert_chain_file_path;
  std::string server_key_file_path;
};

std::vector<std::string> get_entries_of_dir(
  std::string const        & dir_name,
  dir_entry_extract_mode_t extr_mode,
  std::string const        & postfix = "",
  bool                     get_only_entries_that_are_dirs = false,
  std::string const        & exclude_postfix = "",
  std::string const        & prefix = ""
);


test_case_info_t get_test_case_info_from_dir(
  std::string const& test_cases_dir,
  std::string const& test_case
);

cert_path_test_parameters_t parse_test_case_parameters(
  std::string const& test_specs_dir,
  std::string const& sought_test_case
);


std::vector<uint8_t> get_ee_cert_ocsp_response( std::string const& test_cases_dir);

void write_test_result_file(
  std::string const                    & output_dir,
  std::string const                    & test_case_name,
  std::string const                    & info_text,
  cert_path_test_parameters_t const*   expected_result,
  cert_path_validation_result_t const* actual_result,
  Botan::TLS::Alert const*             rec_alert
);

void conclude_test_result_and_write_it(
  std::string const                  & output_dir,
  std::string const                  & test_case_name,
  std::string const                  & info_text,
  bool                               handshake_begun,
  bool                               handshake_completed,
  cert_path_test_parameters_t const* expected_result,
  Botan::TLS::Alert const*           rec_alert
);

std::unique_ptr<Botan::TLS::Alert> try_parse_alert(
  uint8_t const* buf,
  uint32_t       got,
  std::string & message
);

#endif /* h-guard */
