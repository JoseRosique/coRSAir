/*
 * Extracción de los datos de la clave privada
 * usando 2 certificados RSA que comparten un
 * número primo 'p' en su construcción.
 */


#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

// Librerías necesarias para este proyecto (OpenSSL)
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#define BUFFER 1024


/**
 * Cargar un certificado RSA desde un archivo.
 *
 * @param fichero   Ruta del archivo.
 *
 * @return  Clave RSA cargada.
 */
RSA *get_rsa(char *file) {
    // Definir las variables
    RSA *rsa = NULL;        // Clave RSA inicializada a NULL
    FILE *archivo = NULL;  // Archivo
    X509 *cert = NULL;     // Certificado
    EVP_PKEY *pkey = NULL; // Clave pública

    // Abrir el archivo en modo lectura binaria
    archivo = fopen(file, "rb");
    if (archivo == NULL) {
        printf("Error al abrir el fichero '%s'.\n", file);
        return NULL; // Devolver NULL en caso de error
    }

    // Leer el certificado desde el archivo
    cert = PEM_read_X509(archivo, NULL, NULL, NULL);
    if (cert == NULL) {
        printf("Error al leer el certificado desde el file '%s'.\n", file);
        fclose(archivo); // Cerrar el archivo
        return NULL;     // Devolver NULL en caso de error
    }

    // Obtener la clave pública del certificado
    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        printf("Error al obtener la clave pública desde el certificado.\n");
        fclose(archivo); // Cerrar el archivo
        X509_free(cert); // Liberar el certificado
        return NULL;     // Devolver NULL en caso de error
    }

    // Obtener la clave RSA a partir de la clave pública
    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        printf("Error al obtener la clave RSA desde la clave pública.\n");
        fclose(archivo); // Cerrar el archivo
        X509_free(cert); // Liberar el certificado
        EVP_PKEY_free(pkey); // Liberar la clave pública
        return NULL;     // Devolver NULL en caso de error
    }

    // Cerrar el archivo y liberar la memoria
    fclose(archivo);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return rsa;
}


/**
 * Método principal.
 *
 * @return  0 si correcto.
 */
int main(int argc, char *argv[]) {
    // Definir las variables
    unsigned char *res;     // Buffer para los resultados
    unsigned char *sol;     // Buffer para la solución

    BN_CTX *ctx;        // Contexto para el algoritmo RSA
    RSA *privada;       // Clave privada RSA
    BIO *bioprint;      //
    BIGNUM *one;        // Número '1' en formato 'BIGNUM'

    RSA *rsa1;          //               ╭ Clave pública
    BIGNUM *n1;         // Certificado 1 ┼ Número primo 'n'
    BIGNUM *q1;         //               ╰ Número primo 'q'

    RSA *rsa2;          //               ╭ Clave pública
    BIGNUM *n2;         // Certificado 2 ┼ Número primo 'n'
    BIGNUM *q2;         //               ╰ Número primo 'q'

    BIGNUM *p;          // Número primo 'p' común a los dos certificados

    BIGNUM *total;      // Número total de los dos certificados
    BIGNUM *fi1;        // Número de factores primos de 'n'
    BIGNUM *fi2;        // Número de factores primos de 'n'

    BIGNUM *e;          // Exponente de la clave pública
    BIGNUM *d;          // Exponente de la clave privada

    int fd;             // Descriptor del archivo de entrada
    int len;            // Longitud del archivo de entrada

    (void) argc;        // Ignorar el parámetro 'argc'

    // Inicializar las variables
    res = malloc(sizeof(unsigned char) * BUFFER);
    sol = malloc(sizeof(unsigned char) * BUFFER);

    ctx = BN_CTX_new();

    bioprint = BIO_new_fp(stdout, BIO_NOCLOSE);

    rsa1 = get_rsa(argv[1]);
    rsa2 = get_rsa(argv[2]);

    one = BN_new();

    q1 = BN_new();
    q2 = BN_new();

    p = BN_new();
    d = BN_new();

    total = BN_new();
    fi1 = BN_new();
    fi2 = BN_new();

    privada = RSA_new();

    // Cálculos para obtener los datos
    n1 = (BIGNUM*) RSA_get0_n(rsa1);    // Obtener 'n' del certificado 1
    n2 = (BIGNUM*) RSA_get0_n(rsa2);    // Obtener 'n' del certificado 2
    e = (BIGNUM*) RSA_get0_e(rsa1);     // Obtener 'e' del certificado 1

    BN_gcd(p, n1, n2, ctx);             // Obtener 'p' común a los dos certificados
    BN_div(q1, NULL, n1, p, ctx);       // Obtener 'q' del certificado 1
    BN_div(q2, NULL, n2, p, ctx);       // Obtener 'q' del certificado 2

    BN_dec2bn(&one, "1");               // Inicializar 'one' a '1'
    BN_sub(fi1, q1, one);               // Calcular 'fi1' = 'q1' - '1'
    BN_sub(fi2, p, one);                // Calcular 'fi2' = 'p' - '1'
    BN_mul(total, fi1, fi2, ctx);       // Calcular 'total' = 'fi1' * 'fi2'
    BN_mod_inverse(d, e, total, ctx);   // Calcular 'd' = 'e' ^ -1 (mod 'total')

    // Generar la clave privada
    RSA_set0_key(privada, n1, e, d);

    // Asociar los números primos a cada RSA
    RSA_set0_factors(rsa1, p, q1);
    RSA_set0_factors(rsa2, p, q2);

    // Mostrar los datos de los certificados
    printf("\nCERTIFICADO 1:\n");
    RSA_print(bioprint, rsa1, 0);
    RSA_print(bioprint, privada, 0);

    printf("\nCERTIFICADO 2:\n");
    RSA_print(bioprint, rsa2, 0);
    RSA_print(bioprint, privada, 0);

    // Leer el archivo de entrada y descifrar su contenido
    fd = open(argv[3], O_RDONLY);
    len = read(fd, res, BUFFER);
    RSA_private_decrypt(len, res, sol, privada, RSA_PKCS1_PADDING);

    // Mostrar los datos del file
    printf("\nTexto encriptado:\n");
    printf("%s\n", res);

    printf("Texto desencriptado:\n");
    printf("%s\n", sol);

    // Liberar la memoria
    free(res);
    free(sol);

    BN_CTX_free(ctx);
    BIO_free(bioprint);

    BN_free(one);
    BN_free(n1);
    BN_free(q1);
    BN_free(n2);
    BN_free(q2);

    BN_free(p);
    BN_free(d);
    BN_free(e);

    BN_free(total);
    BN_free(fi1);
    BN_free(fi2);

    return 0;
}