#include <stdio.h>
#include <stdbool.h>
#include <openssl/asn1.h>
#include <string.h>
#include <openssl/stack.h>
#include <unistd.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define MAX_ASN_LEN (65535)

#define BITS_IN_BYTE 8

#define NUM_STRING_TYPES 12
static int string_types[NUM_STRING_TYPES] = {12, 18, 19, 22, 26, 27, 25, 28, 29, 30, 20, 21};

static char asn_string[MAX_ASN_LEN];
static char value_string[MAX_ASN_LEN];
static char base64_string[MAX_ASN_LEN];

struct asn1_object_st {
    const char *sn, *ln;
    int nid;
    int length;
    const unsigned char *data;
    int flags;
};

typedef struct asn1_object_st ASN1_OBJECT;

// https://doctrina.org/Base64-With-OpenSSL-C-API.html
int Base64Encode(char* buffer, size_t length, char* b64text) {
	BIO *bio, *b64;
	char* data;
	long data_len;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	
	data_len = BIO_get_mem_data(bio, &data);
	
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	for(long i = 0; i < data_len; i++){
	    b64text[i] = data[i];
	}
	return data_len;
}

void printBinOfHex(unsigned char hex, char* buffer){
    char bits[8] = "00000000";
    for(int i = 0 ; i < BITS_IN_BYTE; i++){
        if(hex & '\x01') bits[i] = '1';
        hex = hex >> 1;
    }
    for(int i = BITS_IN_BYTE - 1; i >= 0; i--){
        buffer[BITS_IN_BYTE - 1 - i] = bits[i];
    }
    return;
}

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
        bool needsBase64 = true;
        int value_string_len = 0;
        printf("\"");
        if(obj->type == 3){ // BIN STRING
            char* spot_in_value = value_string;
            value_string_len = 0;
            for(int i = 0; i < obj->value.asn1_string->length; i++){
                printBinOfHex(obj->value.asn1_string->data[i], spot_in_value);
                value_string_len += BITS_IN_BYTE;
                spot_in_value += BITS_IN_BYTE;
            }
        }
        for(int i = 0; i < NUM_STRING_TYPES; i++){ // STRINGS
            if(obj->type == string_types[i]){
                //for(int i = 0; i < obj->value.asn1_string->length; i++){
                //    printf("%c", obj->value.asn1_string->data[i]);
                //}
                for(int i = 0; i < obj->value.asn1_string->length; i++){
                    value_string[i] = obj->value.asn1_string->data[i];
                    value_string_len = obj->value.asn1_string->length;
                }
                break;
            }
        }
        if(obj->type == 2){ // INTEGER
            char* new_string = "integer";
            value_string_len = strlen(new_string);
            for(unsigned long i = 0; i < strlen(new_string); i++){
                value_string[i] = new_string[i];
            }
            //for(int i = 0; i < obj->value.integer->length; i++){
            //    printf("%02X", obj->value.integer->data[i]);
            //}
            //if(obj->value.integer->length == 0) printf("0");
        }
        if(obj->type == 6){ // OBJ
            value_string_len = i2t_ASN1_OBJECT(value_string, MAX_ASN_LEN, obj->value.object);
            if(value_string_len == -1) return 1;
            //for(int i = 0; i < obj->value.object->length; i++){
            //    printf("0x%x,", obj->value.object->data[i]);
            //}
            // char * name = *((asn1_object_st**)obj->value.object);
        }
        
        if(needsBase64){
            // Convert the value to a base64 encoded version
            long base64len = Base64Encode(value_string, value_string_len, base64_string);
            // Print out the Base64 String
            for(long i = 0; i < base64len; i++){
                printf("%c", base64_string[i]);
            }
        } else {
            // Print out the value string
            for(long i = 0; i < value_string_len; i++){
                printf("%c", value_string[i]);
            }
        }
        printf("\"");
    }
    printf("}");
    return 0;
}

int main(void){
	size_t bytes_read = read(0, asn_string, MAX_ASN_LEN);
    unsigned char* derPointer = (unsigned char*)asn_string;
    ASN1_TYPE* obj = d2i_ASN1_TYPE(NULL, (const unsigned char**)(&derPointer), bytes_read);
    if (obj == NULL) return 1;
    printf("{\"tree\":");
    if(breakIntoTags(obj) == 1) return 1;
    printf("}\n");
    return 0;
}
