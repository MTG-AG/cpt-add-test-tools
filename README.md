# Certification Path Validation Test Tool (CPT) - Extensions

This project provides supplementary tools for the application of the [Certification Path Validation Test Tool (CPT)](https://www.bsi.bund.de/DE/Themen/Kryptografie_Kryptotechnologie/Kryptografie/CPT/cpt_node.html). The CPT is a tool for the creation of X.509 certificates and CRLs for testing purposes. It comes with a test suite that verifies the correctness of implementations of the certification path validation based on the requirements laid down in RFC 5280.

The CPT extensions in this project foremost serve the purpose of facilitating the testing
the certification path validation of TLS servers and clients using test data generated by the CPT. Furthermore, they include test scripts that enable the testing of browsers and IPsec
implementations and support an automated testing procedure for an Apache
web server. The usage of these extensions requires the CPT basis tool as
a prerequisite for the test data generation.

The CPT is maintained by the [German Federal Office for Information
Security (BSI)](https://www.bsi.bund.de/EN/Topics/OtherTopics/CPT/cpt_node.html). The technical maintenance of the CPT extensions is handled by [cryptosource GmbH](https://www.cryptosource.de).


# Other CPT resources on the web

The following other resources for the CPT exist on web:

* The [CPT main project page](https://www.bsi.bund.de/EN/Topics/OtherTopics/CPT/cpt_node.html) is maintained by the German Federal Office for Information
Security (BSI).
* The CPT Basis Tool, which generates X.509 certificates and CRLs based on a
  test specification is also [available on github](https://github.com/MTG-AG/cpt/) and is technically maintained by [MTG AG](https://www.mtg.de/).
* [A github project](https://github.com/cryptosource-GmbH/cpt-native-lib-test) for a tool for the testing the certification path validation implemented in C/C++ cryptographic libraries based on the test data generated by the CPT.


# Documentation

The documentation for the installation and usage of the CPT extensions can be
[downloaded from the project
website](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CPT/CPT-Tool-Extensions-User-Documentation_v1_1.pdf?__blob=publicationFile&v=2).


# Quick start for the TLS test tool

In order to get quickly started with the TLS test tool extension for the CPT,
proceed as follows:

* clone or download this github project onto a Linux system
* install the cmake utility using `apt-get install cmake`
* install the C++ Boost libraries in version 1.64 to the default installation
  location `/opt/boost_1_64`. The subfolders `/opt/boost_1_64/lib` and `/opt/boost_1_64/include` are expected. Newer versions of the boost libraries may also work but have not been tested.
* install the Botan library in version 2.2.0. Newer versions of Botan may also
  work but have not been tested.
* for more details on the installation of the Boost libraries and Botan refer to Section 3.2 in the [documentation](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CPT/CPT-Tool-Extensions-User-Documentation_v1_1.pdf?__blob=publicationFile&v=2).
* execute `cmake .`
* execute `make`
* start the TLS test client: `./build/modul_tls tls_client <hostname> --test_main_dir=<cpt directory> 
--test_case=<test case name> --port=<port> --result_dir=<output directory>`
* start the TLS test server: `./build/modul_tls tls_server --test_main_dir=<cpt directory> 
--test_case=<test case name> --port=<port> --result_dir=<output directory> [
--timeout=<timeout seconds> --stay ]`
* for more details on running the TLS test tools, refer to Section 3.3 in the
  [documentation](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CPT/CPT-Tool-Extensions-User-Documentation_v1_1.pdf?__blob=publicationFile&v=2). 
