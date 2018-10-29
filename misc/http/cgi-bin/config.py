#! /usr/bin/python

class config:
    test_results_dir ="../../run/mod_browser_test_results" 
    dyn_srv_port_file = "../../run/dyn_server_port"
    dyn_srv_port_min = 4450 
    dyn_srv_port_max = 4550

    test_cases_dir = "../../../../third_party_libs/certification_path_tool/output"

    # points to the HTML template for web site generation
    template_file = "../../http_templates/test_list_tmpl.html"

    # points to the directory from which tls test server is started
    mod_tls_cwd = "../../../"
    cpt_dir_rel_to_mod_tls_cwd = "../third_party_libs/certification_path_tool"

    # Boolean value indicating whether the TLS testserver sends the stapled
    # response for the EE (i.e. server) certificate contained in the
    # ocspResonse output directory.
    do_use_ocsp_stapling=True
