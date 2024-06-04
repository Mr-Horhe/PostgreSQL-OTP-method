#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#define MAX_LINES 3 
#define MAX_LINE_LENGTH 100

int main(){

    // FILE * file=fopen("/tmp/password","r");
    // char lines[MAX_LINES][MAX_LINE_LENGTH];
    // int lines_cnt = 0;
    // while(fgets(lines[lines_cnt], MAX_LINE_LENGTH, file) && lines_cnt < MAX_LINES){
    //     lines_cnt++;
    // }
    // fclose(file);

    FILE *fp = fopen("private.pem", "r");
    char key[2048];
    fread(key, 1, 2048, fp); // Чтение закрытого ключа из файла
    fclose(fp);
    BIO *bio = BIO_new_mem_buf(key, -1); // Создание BIO из ключа
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL); // Загрузка закрытого ключа RSA
    BIO_free(bio);

    unsigned char encrypted[256];
    FILE *in = fopen("/pg/data/encrypted.bin", "rb");
    int encrypted_length = fread(encrypted, 1, 256, in); // Чтение из файла
    fclose(in);

    char decrypted[100];
    int enc_result = RSA_private_decrypt(encrypted_length, encrypted, (unsigned char*)decrypted, rsa, RSA_PKCS1_PADDING); // Расшифровка

    if(enc_result == -1) {
        printf("Ошибка расшифровки\n");
    } else {
        decrypted[enc_result] = '\0'; // Добавляем нулевой символ в конец строки
    }
    char *token;
    char *point = "|";

    token = strtok(decrypted, point);

    char parameters[3][100];
    int k = 0;
    while (token != NULL){
        strncpy(parameters[k], token, sizeof(parameters[k]));
        k++;
        //printf("%s\n", token);
        token = strtok(NULL, point);
    }
    //printf("\n%s\n", parameters[2]);
    int seed = atoi(parameters[0]);
    //printf("\n%d\n", seed);
    srand(--seed);
    char mask[strlen(parameters[2])];
    memcpy(mask, parameters[2], sizeof(parameters[2]));
    //printf("\n%s\n", parameters[2]);
    int pass_len = atoi(parameters[1]);
    //printf("\n%d\n", pass_len);
    char result[pass_len];
    

    {
            char allowed_chars[]="0123456789abcdefghkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ";
            char allowed_chars_9[]="0123456789";
            char allowed_chars_A[]="ABCDEFGHIJKLMNPQRSTUVWXYZ";
            char allowed_chars_a[]="abcdefghkmnopqrstuvwxyz";
            char allowed_chars_Hash[]="~!@#$%^&*()_+-=";
            
            for(int i=0; i< pass_len ; ++i){
                    if(i<strlen(mask)){
                        char mask_char = mask[i];
                        if(mask_char=='9'){
                            int rnd = rand();
                            int idx = rnd % (sizeof(allowed_chars_9)-1);
                            result[i]=allowed_chars_9[idx];
                        }else
                        if(mask_char=='A'){
                            int rnd = rand();
                            int idx = rnd % (sizeof(allowed_chars_A)-1);
                            result[i]=allowed_chars_A[idx];
                        }else
                        if(mask_char=='a'){
                            int rnd = rand();
                            int idx = rnd % (sizeof(allowed_chars_a)-1);
                            result[i]=allowed_chars_a[idx];
                        }else
                        if(mask_char=='#'){
                            int rnd = rand();
                            int idx = rnd % (sizeof(allowed_chars_Hash)-1);
                            result[i]=allowed_chars_Hash[idx];
                        }else{
                            int rnd = rand();
                            int idx = rnd % (sizeof(allowed_chars)-1);
                            result[i]=allowed_chars[idx];
                        }

                    }else{
                        int rnd = rand();
                        int idx = rnd % (sizeof(allowed_chars)-1);
                        result[i]=allowed_chars[idx];
                    }
            }
            result[pass_len]=0;
            printf("%s\n", result);
    }

}