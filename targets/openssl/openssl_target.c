#include <stdio.h>
#include <openssl/asn1.h>

#define MAX_ASN_LEN (32768)
static char asn_string[MAX_ASN_LEN];

int main(void){
    printf("Hello World!\n");
    fgets(asn_string, MAX_ASN_LEN, stdin);
    printf("%s", asn_string);
    return 0;
}