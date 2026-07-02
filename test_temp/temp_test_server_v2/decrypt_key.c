#include <stdio.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/x509.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <encrypted_pem> <password>\n", argv[0]);
        return 1;
    }
    
    SM2_KEY key;
    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }
    if (sm2_private_key_info_decrypt_from_pem(&key, argv[2], in) != 1) {
        fprintf(stderr, "Failed to decrypt %s\n", argv[1]);
        fclose(in);
        return 1;
    }
    fclose(in);
    
    // Write unencrypted PKCS8
    char out_path[256];
    snprintf(out_path, sizeof(out_path), "%s.unencrypted", argv[1]);
    FILE *fp = fopen(out_path, "wb");
    if (!fp) {
        fprintf(stderr, "Cannot create %s\n", out_path);
        return 1;
    }
    
    if (sm2_private_key_info_to_pem(&key, fp) != 1) {
        fprintf(stderr, "Failed to write PEM to %s\n", out_path);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    printf("Decrypted %s -> %s\n", argv[1], out_path);
    return 0;
}
