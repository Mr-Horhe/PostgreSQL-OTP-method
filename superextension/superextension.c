#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include "utils/geo_decls.h"
#include "varatt.h"
#include "funcapi.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "mtwister.h"


#define MAX_PASSWORD_LEN 1000
#define MIN_PASSWORD_LEN 8

char *
text_to_cstring(const text *t);


PG_MODULE_MAGIC;


//DR
//begin copy-paste from varlena.c
char *
text_to_cstring(const text *t)
 {
     /* must cast away the const, unfortunately */
     text       *tunpacked = pg_detoast_datum_packed(unconstify(text *, t));
     int         len = VARSIZE_ANY_EXHDR(tunpacked);
     char       *result;
  
     result = (char *) palloc(len + 1);
     memcpy(result, VARDATA_ANY(tunpacked), len);
     result[len] = '\0';
  
     if (tunpacked != t)
         pfree(tunpacked);
  
     return result;
 }
//end copy-paste from varlena.c




//DR 
//Some kind of optimization
//Structure will be reused between calls
typedef struct MyContext_data
{
    int seed_num;
    int  pass_len;	
    char *mask;
	char *result;  
}MyContext_data;


PG_FUNCTION_INFO_V1(superfunction);

Datum
superfunction(PG_FUNCTION_ARGS)
{
    FuncCallContext     *funcctx;
    int                  call_cntr;    
    TupleDesc            tupdesc;
    AttInMetadata       *attinmeta;

    /* stuff done only on the first call of the function */
    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext   oldcontext;
        struct          MyContext_data *myContext_data;

        /* create a function context for cross-call persistence */
        funcctx = SRF_FIRSTCALL_INIT();

        /* switch to memory context appropriate for multiple function calls */
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        /* total number of tuples to be returned */
        funcctx->max_calls = 1;


        /* Build a tuple descriptor for our result type */
        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function returning record called in context "
                            "that cannot accept type record")));

        /*
         * generate attribute metadata needed later to produce tuples from raw
         * C strings
         */
        attinmeta = TupleDescGetAttInMetadata(tupdesc);
        funcctx->attinmeta = attinmeta;


        /*begin extract the_char from the 2nd param*/
        

        // Аллоцируем котекст, который будет одинаковый между вызовами
        myContext_data = (struct MyContext_data*)palloc(1*sizeof(MyContext_data));
        //Пролучаем 1й параметр функции как int32
        myContext_data->pass_len   = PG_GETARG_INT32(0);
        if (PG_GETARG_INT32(2) == 0){
            FILE * file=fopen("/tmp/password","r");
            char line[100];
            fgets(line, sizeof(line), file);
            fclose(file);
            int s_num = atoi(line);
            myContext_data->seed_num = s_num;
        }else{
            myContext_data->seed_num = PG_GETARG_INT32(2);
        }
        // if(myContext_data->pass_len < 0)  
        //     ereport(ERROR,
        //             (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
        //              errmsg("Bad input. Negative size")));
                     
        if(myContext_data->pass_len >= MAX_PASSWORD_LEN)  
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("Bad input. Over size")));

        if(myContext_data->pass_len < MIN_PASSWORD_LEN)  
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("Bad input. The password must contain more than 8 characters")));
        
        //Пролучаем 1й параметр функции как char*            
        myContext_data->mask       = text_to_cstring(PG_GETARG_TEXT_PP(1)); //palloc here 
        //Заранее аллоцируем память под результат
        myContext_data->result     = (char*)palloc(MAX_PASSWORD_LEN*sizeof(char));  //reserve for output
        //Освобождать необязательно , PG деаллоцирует все сразу после выполнения sql запроса, в котором участвует функция

        funcctx->user_fctx = (void*)myContext_data;
	    /*end extract the_char from the 2nd param*/
        MemoryContextSwitchTo(oldcontext);
    }//end init

    /* stuff done on every call of the function */
    funcctx = SRF_PERCALL_SETUP();

    call_cntr = funcctx->call_cntr;
    attinmeta = funcctx->attinmeta;

    if (call_cntr < 1)    /* do when there is more left to send */
    {
        char       **values;
        HeapTuple    tuple;
        Datum        result;

        /*
         * Prepare a values array for building the returned tuple.
         * This should be an array of C strings which will
         * be processed later by the type input functions.
         */

//	uint64 out_str_len = call_cntr+1;
    
	    MyContext_data *myContext_data = (MyContext_data*)funcctx->user_fctx;
        // no for(){}
	    //param2_out_data->result[call_cntr] = call_cntr % 2 ? 'A' : 'B'; //->result is reused between calls 
	    //param2_out_data->result[call_cntr+1] = '\0';


        {
            MTRand r = seedRand(myContext_data->seed_num);
            //srand(myContext_data->seed_num);
            char allowed_chars[]="0123456789abcdefghkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ";
            char allowed_chars_9[]="0123456789";
            char allowed_chars_A[]="ABCDEFGHIJKLMNPQRSTUVWXYZ";
            char allowed_chars_a[]="abcdefghkmnopqrstuvwxyz";
            char allowed_chars_Hash[]="~!@#$%^&*()_+-=";            
            
            for(int i=0; i< myContext_data->pass_len ; ++i){
                    if(i<strlen(myContext_data->mask)){
                        char mask_char = myContext_data->mask[i];
                        if(mask_char=='9'){
                            int rnd = genRandLong(&r);
                            int idx = rnd % (sizeof(allowed_chars_9)-1);
                            myContext_data->result[i]=allowed_chars_9[idx];
                        }else
                        if(mask_char=='A'){
                            int rnd = genRandLong(&r);
                            int idx = rnd % (sizeof(allowed_chars_A)-1);
                            myContext_data->result[i]=allowed_chars_A[idx];
                        }else
                        if(mask_char=='a'){
                            int rnd = genRandLong(&r);
                            int idx = rnd % (sizeof(allowed_chars_a)-1);
                            myContext_data->result[i]=allowed_chars_a[idx];
                        }else
                        if(mask_char=='#'){
                            int rnd = genRandLong(&r);
                            int idx = rnd % (sizeof(allowed_chars_Hash)-1);
                            myContext_data->result[i]=allowed_chars_Hash[idx];
                        }else{
                            int rnd = genRandLong(&r);
                            int idx = rnd % (sizeof(allowed_chars)-1);
                            myContext_data->result[i]=allowed_chars[idx];
                        }

                    }else{
                        int rnd = genRandLong(&r);
                        int idx = rnd % (sizeof(allowed_chars)-1);
                        myContext_data->result[i]=allowed_chars[idx];
                    }

            }
            myContext_data->seed_num = ++myContext_data->seed_num;
            myContext_data->result[myContext_data->pass_len]=0;
            
            {
                char str[100];
                sprintf(str, "%d|%d|%s", myContext_data->seed_num, myContext_data->pass_len, myContext_data->mask); // Преобразование переменных в char[] и объединение

                FILE *fl = fopen("public.pem", "r");
                char key[2048];
                fread(key, 1, 2048, fl);
                fclose(fl);
                BIO *bio = BIO_new_mem_buf(key, -1);
                RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL); // Загрузка открытого ключа RSA
                BIO_free(bio);
                

                unsigned char encrypted[256];
                int enc_result = RSA_public_encrypt(strlen(str), (unsigned char*)str, encrypted, rsa, RSA_PKCS1_PADDING); // Шифрование
                
                FILE * fp=fopen("/tmp/password","w");
                fprintf(fp, "%d\n", myContext_data->seed_num);
                //fwrite( enc_result,1,strlen( enc_result), fp);
                fwrite( myContext_data->mask,1,strlen( myContext_data->mask), fp);
                fprintf(fp, "\n%d\n", myContext_data->pass_len);
                fwrite( myContext_data->result,1,strlen( myContext_data->result), fp);
                fclose(fp);
                FILE *out = fopen("encrypted.bin", "wb");
                fwrite(encrypted, 1, enc_result, out); // Запись в файл
                fclose(out);
            }
        }


        values = (char **) palloc(2 * sizeof(char *));
        values[0] = (char *) palloc(16 * sizeof(char));
        values[1] = myContext_data->result;


        snprintf(values[0], 16, "%d", call_cntr+1);
	 

        /* build a tuple */
        tuple = BuildTupleFromCStrings(attinmeta, values);

        /* make the tuple into a datum */
        result = HeapTupleGetDatum(tuple);

        /* clean up (this is not really necessary) */
        pfree(values[0]);

        pfree(values);

        SRF_RETURN_NEXT(funcctx, result);
    }
    else    /* do when there is no more left */
    {
        MyContext_data *myContext_data = (MyContext_data*)funcctx->user_fctx;
        pfree(myContext_data->result); 
        pfree(funcctx->user_fctx);
        SRF_RETURN_DONE(funcctx);
    }
}





