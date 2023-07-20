#include <stdint.h>
#include <string.h>
#include <wget/wget.h>

#define MAX_URL_LEN (32768)
#define MAX_PORT_LEN (256)
static char url_string[MAX_URL_LEN];

int main(void) {
    fread(url_string, 1, MAX_URL_LEN, stdin);
    wget_iri *const parsed_url = wget_iri_parse(url_string, "utf-8");
    if (parsed_url == NULL) {
        return 1;
    }

    char const *scheme_str = NULL;
    if (parsed_url->scheme == 0) {
        scheme_str = "http";
    } else if (parsed_url->scheme == 1) {
        scheme_str = "https";
    }

    char const *const user_str = parsed_url->userinfo;
    char const *const password_str = parsed_url->password;
    char *userinfo_str = NULL;
    if (user_str != NULL && password_str == NULL) {
        userinfo_str = calloc(strlen(user_str) + 1, 1);
        if (userinfo_str == NULL) {
            return 2;
        }
        strcpy(userinfo_str, user_str);
    } else if (user_str == NULL && password_str != NULL) {
        userinfo_str = calloc(2, 1);
        if (userinfo_str == NULL) {
            return 2;
        }
        userinfo_str[0] = ':';
        userinfo_str[1] = '\0';
        userinfo_str = realloc(userinfo_str, 1 + strlen(password_str) + 1);
        if (userinfo_str == NULL) {
            return 2;
        }
        strcat(userinfo_str, password_str);
    } else if (user_str != NULL && password_str != NULL) {
        userinfo_str = calloc(strlen(user_str) + 1 + strlen(password_str) + 1, 1);
        if (userinfo_str == NULL) {
            return 2;
        }
        strcpy(userinfo_str, user_str);
        strcat(userinfo_str, ":");
        strcat(userinfo_str, password_str);
    }

    char *const scheme_b64 = wget_base64_encode_alloc(scheme_str, scheme_str != NULL ? strlen(scheme_str) : 0);
    char *const host_b64 = wget_base64_encode_alloc(parsed_url->host, parsed_url->host != NULL ? strlen(parsed_url->host) : 0);
    char *const userinfo_b64 = wget_base64_encode_alloc(userinfo_str, userinfo_str != NULL ? strlen(userinfo_str) : 0);
    char port_str[MAX_PORT_LEN];
    snprintf(port_str, sizeof(port_str), "%d", parsed_url->port);
    char *const port_b64 = wget_base64_encode_alloc(port_str, strlen(port_str));
    char *const path_b64 = wget_base64_encode_alloc(parsed_url->path, parsed_url->path != NULL ? strlen(parsed_url->path) : 0);
    char *const query_b64 = wget_base64_encode_alloc(parsed_url->query, parsed_url->query != NULL ? strlen(parsed_url->query) : 0);
    char *const fragment_b64 = wget_base64_encode_alloc(parsed_url->fragment, parsed_url->fragment != NULL ? strlen(parsed_url->fragment) : 0);

    printf("{\"scheme\":\"%s\",\"userinfo\":\"%s\",\"host\":\"%s\",\"port\":\"%s\",\"path\":\"%s\",\"query\":\"%s\",\"fragment\":\"%s\"}\n", scheme_b64, userinfo_b64, host_b64, port_b64, path_b64, query_b64, fragment_b64);

    free(parsed_url);
    free(userinfo_str);
    free(scheme_b64);
    free(userinfo_b64);
    free(host_b64);
    free(port_b64);
    free(path_b64);
    free(query_b64);
    free(fragment_b64);
}
