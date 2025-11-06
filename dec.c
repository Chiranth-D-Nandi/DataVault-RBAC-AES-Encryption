#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "dec.h"

// Helper: removes '_encrypted' from the base name, appends '_decrypted', and preserves extension.
void get_decrypted_filename(const char *infile, char *outfile, size_t outsize) {
    const char *dot = strrchr(infile, '.');
    if (dot) {
        size_t base_len = dot - infile;
        // Look for "_encrypted" before the extension
        const char *enc = NULL;
        for (const char *p = infile; p < dot; ++p) {
            if (strncmp(p, "_encrypted", 10) == 0 && p + 10 == dot) {
                enc = p;
                break;
            }
        }
        if (enc) {
            size_t enc_base_len = enc - infile;
            if (enc_base_len + 10 + strlen(dot) + 1 > outsize) {
                strncpy(outfile, infile, outsize - 1);
                outfile[outsize - 1] = '\0';
                return;
            }
            strncpy(outfile, infile, enc_base_len);
            outfile[enc_base_len] = '\0';
            strcat(outfile, "_decrypted");
            strcat(outfile, dot);
        } else {
            // No "_encrypted" before extension, just insert "_decrypted"
            if (base_len + 10 + strlen(dot) + 1 > outsize) {
                strncpy(outfile, infile, outsize - 1);
                outfile[outsize - 1] = '\0';
                return;
            }
            strncpy(outfile, infile, base_len);
            outfile[base_len] = '\0';
            strcat(outfile, "_decrypted");
            strcat(outfile, dot);
        }
    } else {
        // No extension, just append _decrypted
        if (strlen(infile) + 10 + 1 > outsize) {
            strncpy(outfile, infile, outsize - 1);
            outfile[outsize - 1] = '\0';
            return;
        }
        strcpy(outfile, infile);
        strcat(outfile, "_decrypted");
    }
}

int decrypt(const char *infile, const char *keyfile) {
    FILE *fin = fopen(infile, "rb");
    if (!fin) {
        printf("Error opening input file.\n");
        return 1;
    }

    FILE *kf = fopen(keyfile, "rb");
    if (!kf) {
        fclose(fin);
        printf("Error opening key file.\n");
        return 1;
    }

    unsigned char key[32], iv[16];
    if (fread(key, 1, 32, kf) != 32 || fread(iv, 1, 16, kf) != 16) {
        printf("Key file corrupt or incomplete.\n");
        fclose(fin);
        fclose(kf);
        return 1;
    }
    fclose(kf);

    // Output file with _decrypted and preserved extension
    char outfile[512];
    get_decrypted_filename(infile, outfile, sizeof(outfile));
    FILE *fout = fopen(outfile, "wb");
    if (!fout) {
        printf("Error opening output file.\n");
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

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        printf("Error initializing decryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return 1;
    }

    unsigned char inbuf[4096], outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            printf("Decryption update error.\n");
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
    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        printf("Decryption final error. Possibly wrong key or corrupted file.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return 1;
    }
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);
    printf("Decryption successful! Output: %s\n", outfile);
    return 0;
}