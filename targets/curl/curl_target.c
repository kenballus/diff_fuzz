#include <stdlib.h>
#include <string.h>

#include "curl/include/curl/curl.h"
#include "curl/lib/curl_base64.h"

#define MAX_URL_LEN (32768)
static size_t unused;
static char url_string[MAX_URL_LEN];

int main(void) {
    fread(url_string, 1, MAX_URL_LEN, stdin);

    CURLU *const parsed_url = curl_url();
    CURLUcode const rc = curl_url_set(parsed_url, CURLUPART_URL, url_string, CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME);
    if (rc != CURLUE_OK) {
        return 1;
    }

    char *scheme = NULL;
    char *user = NULL;
    char *password = NULL;
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    char *query = NULL;
    char *fragment = NULL;

    char *b64_scheme = NULL;
    char *b64_userinfo = NULL;
    char *b64_password = NULL;
    char *b64_host = NULL;
    char *b64_port = NULL;
    char *b64_path = NULL;
    char *b64_query = NULL;
    char *b64_fragment = NULL;

    curl_url_get(parsed_url, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(parsed_url, CURLUPART_USER, &user, 0);
    curl_url_get(parsed_url, CURLUPART_PASSWORD, &password, 0);
    curl_url_get(parsed_url, CURLUPART_HOST, &host, 0);
    curl_url_get(parsed_url, CURLUPART_PORT, &port, 0);
    curl_url_get(parsed_url, CURLUPART_PATH, &path, 0);
    curl_url_get(parsed_url, CURLUPART_QUERY, &query, 0);
    curl_url_get(parsed_url, CURLUPART_FRAGMENT, &fragment, 0);
    // Leaving off OPTIONS and ZONEID for now.

    if (scheme != NULL) {
        Curl_base64_encode(scheme, 0, &b64_scheme, &unused);
    }
    if (user != NULL && password != NULL) {
        user = realloc(user, strlen(user) + 1 + strlen(password) + 1);
        if (user == NULL) {
            return 2;
        }
        strcat(user, ":");
        strcat(user, password);
        Curl_base64_encode(user, 0, &b64_userinfo, &unused);
    } else if (user != NULL && password == NULL) {
        Curl_base64_encode(user, 0, &b64_userinfo, &unused);
    } else if (user == NULL && password != NULL) {
        user = malloc(2);
        if (user == NULL) {
            return 2;
        }
        user[0] = ':';
        user[1] = '\0';
        user = realloc(user, 1 + strlen(password) + 1);
        if (user == NULL) {
            return 2;
        }
        strcat(user, password);
        Curl_base64_encode(user, 0, &b64_userinfo, &unused);
    }
    if (host != NULL) {
        Curl_base64_encode(host, 0, &b64_host, &unused);
    }
    if (port != NULL) {
        Curl_base64_encode(port, 0, &b64_port, &unused);
    }
    if (path != NULL) {
        Curl_base64_encode(path, 0, &b64_path, &unused);
    }
    if (query != NULL) {
        Curl_base64_encode(query, 0, &b64_query, &unused);
    }
    if (fragment != NULL) {
        Curl_base64_encode(fragment, 0, &b64_fragment, &unused);
    }

    printf("{\"scheme\":\"%s\",\"userinfo\":\"%s\",\"host\":\"%s\",\"port\":\"%s\",\"path\":\"%s\",\"query\":\"%s\",\"fragment\":\"%s\"}\n",
           b64_scheme != NULL ? b64_scheme : "",
           b64_userinfo != NULL ? b64_userinfo : "",
           b64_host != NULL ? b64_host : "",
           b64_port != NULL ? b64_port : "",
           b64_path != NULL ? b64_path : "",
           b64_query != NULL ? b64_query : "",
           b64_fragment != NULL ? b64_fragment : "");

    free(b64_scheme);
    free(b64_userinfo);
    free(b64_password);
    free(b64_host);
    free(b64_port);
    free(b64_path);
    free(b64_query);
    free(b64_fragment);

    free(scheme);
    free(user);
    free(password);
    free(host);
    free(port);
    free(path);
    free(query);
    free(fragment);

    curl_url_cleanup(parsed_url);
}
