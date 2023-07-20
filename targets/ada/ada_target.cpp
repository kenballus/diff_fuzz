#include <iostream>
#include <boost/beast.hpp>

#include "ada/singleheader/ada.h"

using boost::beast::detail::base64::encode;
using boost::beast::detail::base64::encoded_size;

int main() {
    std::string input;
    std::string line;
    while (std::getline(std::cin, line)) {
        input += line;
    }

    auto const &parsed_url = ada::parse<ada::url_aggregator>(input);
    if (!parsed_url) {
        return 1;
    }

    std::string scheme(parsed_url->get_protocol());
    if (scheme.back() == ':') {
        scheme.pop_back();
    }
    std::string userinfo(std::string(parsed_url->get_username()) + (parsed_url->has_password() ? (std::string(":") + std::string(parsed_url->get_password())) : std::string()));
    std::string host(parsed_url->get_hostname());
    std::string port(parsed_url->get_port());
    std::string path(parsed_url->get_pathname());
    std::string query(parsed_url->get_search());
    if (query[0] == '?') {
        query = query.substr(1);
    }
    std::string fragment(parsed_url->get_hash());
    if (fragment[0] == '#') {
        fragment = fragment.substr(1);
    }

    char *const scheme_b64 = new char[encoded_size(scheme.length()) + 1];
    char *const userinfo_b64 = new char[encoded_size(userinfo.length()) + 1];
    char *const host_b64 = new char[encoded_size(host.length()) + 1];
    char *const port_b64 = new char[encoded_size(port.length()) + 1];
    char *const path_b64 = new char[encoded_size(path.length()) + 1];
    char *const query_b64 = new char[encoded_size(query.length()) + 1];
    char *const fragment_b64 = new char[encoded_size(fragment.length()) + 1];

    scheme_b64[encode(scheme_b64, scheme.c_str(), scheme.length())] = '\0';
    userinfo_b64[encode(userinfo_b64, userinfo.c_str(), userinfo.length())] = '\0';
    host_b64[encode(host_b64, host.c_str(), host.length())] = '\0';
    port_b64[encode(port_b64, port.c_str(), port.length())] = '\0';
    path_b64[encode(path_b64, path.c_str(), path.length())] = '\0';
    query_b64[encode(query_b64, query.c_str(), query.length())] = '\0';
    fragment_b64[encode(fragment_b64, fragment.c_str(), fragment.length())] = '\0';

    std::cout << "{\"scheme\":\""<< scheme_b64
              << "\",\"userinfo\":\"" << userinfo_b64
              << "\",\"host\":\"" << host_b64
              << "\",\"port\":\"" << port_b64
              << "\",\"path\":\"" << path_b64
              << "\",\"query\":\"" << query_b64
              << "\",\"fragment\":\"" << fragment_b64
              << "\"}\n";

    delete[] scheme_b64;
    delete[] userinfo_b64;
    delete[] host_b64;
    delete[] port_b64;
    delete[] path_b64;
    delete[] query_b64;
    delete[] fragment_b64;
}
