#include <iostream>

#include <boost/url/src.hpp>
#include <boost/beast.hpp>

using boost::beast::detail::base64::encode;
using boost::beast::detail::base64::encoded_size;

int main() {
    std::string input;
    std::string line;
    while (std::getline(std::cin, line)) {
        input += line;
    }

    boost::urls::url const u(input);

    std::string const scheme(u.scheme());
    std::string const userinfo(u.userinfo());
    std::string const host(u.host());
    std::string const port(u.port());
    std::string const path(u.path());
    std::string const query(u.query());
    std::string const fragment(u.fragment());

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
