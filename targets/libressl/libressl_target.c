#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/objects.h>

#define MAX_ASN_LEN (65535)
#define MAX_TEMP_LEN (65535)

#define BITS_IN_BYTE 8

#define NUM_STRING_TYPES 12
static int string_types[NUM_STRING_TYPES] = {12, 18, 19, 22, 26, 27, 25, 28, 29, 30, 20, 21};

static char asn_string[MAX_ASN_LEN];

struct asn1_object_st {
    const char *sn, *ln;
    int nid;
    int length;
    const unsigned char *data;  /* data remains const after init */
    int flags;                  /* Should we free this one */
};

void printBinOfHex(unsigned char hex){
    char bits[8] = "00000000";
    for(int i = 0 ; i < BITS_IN_BYTE; i++){
        if(hex & '\x01') bits[i] = '1';
        hex = hex >> 1;
    }
    for(int i = BITS_IN_BYTE - 1; i >= 0; i--){
        printf("%c", bits[i]);
    }
    return;
}
/*
int breakIntoTags(ASN1_TYPE* obj){
    printf("{\"tag\":\"%d\",\"value\":", obj->type);
    if(obj->type == 16 || obj->type == 17){
        unsigned char* p = obj->value.sequence->data;
        void* seq = NULL;
        if(obj->type == 16){
            seq = d2i_ASN1_SEQUENCE_ANY(NULL, (const unsigned char**)(&p), obj->value.sequence->length);
        } else {
            seq = d2i_ASN1_SET_ANY(NULL, (const unsigned char**)(&p), obj->value.set->length);
        }
        if(seq == NULL) return 1;
        printf("[");
        int seq_count = sk_ASN1_TYPE_num(seq);
        for(int i = 0; i < seq_count; i++){
            ASN1_TYPE* child = sk_ASN1_TYPE_shift(seq);
            if(child == NULL) return 1;
            if(i != 0) printf(",");
            breakIntoTags(child);
        }
        printf("]");
    } else {
        printf("\"");
        if(obj->type == 3){ // BIN STRING
            for(int i = 0; i < obj->value.asn1_string->length; i++){
                printBinOfHex(obj->value.asn1_string->data[i]);
            }
        }
        for(int i = 0; i < NUM_STRING_TYPES; i++){ // STRINGS
            if(obj->type == string_types[i]){
                for(int i = 0; i < obj->value.asn1_string->length; i++){
                    printf("%c", obj->value.asn1_string->data[i]);
                }
                break;
            }
        }
        if(obj->type == 2){ // INTEGER
            for(int i = 0; i < obj->value.integer->length; i++){
                printf("%02X", obj->value.integer->data[i]);
            }
            if(obj->value.integer->length == 0) printf("0");
        }
        if(obj->type == 6){ // OBJ ID
            //BIO* bioOut = BIO_new_fp(stdout, BIO_CLOSE);
            // int p = OBJ_obj2nid(obj->value.object);
            // char* q = &p;

            // i2t_ASN1_OBJECT(temp_string, MAX_TEMP_LEN, obj->value.object);
            // printf("%s", temp_string);
            for(int i = 0; i < obj->value.object->length; i++){
                printf("0x%x,", obj->value.object->data[i]);
            }
            // char * name = *((asn1_object_st**)obj->value.object);
        }
        printf("\"");
    }
    printf("}");
    return 0;
}*/

int main(void){
	size_t bytes_read = read(0, asn_string, MAX_ASN_LEN);
    unsigned char* derPointer = (unsigned char*)asn_string;
    // ASN1_TYPE* obj = d2i_ASN1_TYPE(NULL, (const unsigned char**)(&derPointer), bytes_read);
    // if (obj == NULL) return 1;
    BIO* bp_out = BIO_new_fp(stdout, BIO_CLOSE);
    printf("{\"tree\":");
    ASN1_parse(bp_out, derPointer, bytes_read, 0);
    // if(breakIntoTags(obj) == 1) return 1;
    printf("}\n");
    BIO_free(bp_out);
    return 0;
}