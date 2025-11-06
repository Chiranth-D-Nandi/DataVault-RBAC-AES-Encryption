#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "enc.h"

// Helper: insert _encrypted before extension, or append if no extension
void get_encrypted_filename(const char *infile, char *outfile, size_t outsize) {
    const char *dot = strrchr(infile, '.');
    if (dot) {
        size_t base_len = dot - infile;
        if (base_len + 10 + strlen(dot) + 1 > outsize) { // 10 for "_encrypted"
            strncpy(outfile, infile, outsize - 1);
            outfile[outsize - 1] = '\0';
            return;
        }
        strncpy(outfile, infile, base_len);
        outfile[base_len] = '\0';
        strcat(outfile, "_encrypted");
        strcat(outfile, dot);
    } else {
        if (strlen(infile) + 10 + 1 > outsize) {
            strncpy(outfile, infile, outsize - 1);
            outfile[outsize - 1] = '\0';
            return;
        }
        strcpy(outfile, infile);
        strcat(outfile, "_encrypted");
    }
}

int final(const char *infile) {
    FILE *fin = fopen(infile, "rb");
    if (!fin) {
        printf("Error opening input file.\n");
        return 1;
    }

    unsigned char key[32], iv[16];
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        printf("Error generating key or IV.\n");
        fclose(fin);
        return 1;
    }

    // Save key and IV to file
    char keyfile[512];
    get_encrypted_filename(infile, keyfile, sizeof(keyfile));
    strcat(keyfile, ".key");
    FILE *kf = fopen(keyfile, "wb");
    if (!kf) {
        printf("Error opening key file.\n");
        fclose(fin);
        return 1;
    }
    fwrite(key, 1, 32, kf);
    fwrite(iv, 1, 16, kf);
    fclose(kf);

    // Output file with _encrypted and preserved extension
    char outfile[512];
    get_encrypted_filename(infile, outfile, sizeof(outfile));
    FILE *fout = fopen(outfile, "wb");
    if (!fout) {
        printf("Error opening encrypted file.\n");
        fclose(fin);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating cipher context.\n");
        fclose(fin);
        fclose(fout);
        return 1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        printf("Error initializing encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return 1;
    }

    unsigned char inbuf[4096], outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            printf("Encryption update error.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin);
            fclose(fout);
            return 1;
        }
        fwrite(outbuf, 1, outlen, fout);
    }
    if (ferror(fin)) {
        printf("Error reading input file.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return 1;
    }
    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        printf("Encryption final error.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return 1;
    }
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);
    printf("Encryption successful! Output: %s\nKey: %s\n", outfile, keyfile);
    return 0;
}