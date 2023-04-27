#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Libraries of Openssl
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"

#define BUFFER 1024

// Upload an RSA certificate from a file.
RSA	*get_rsa(char *file)
{
	// Define variables.
	RSA *rsa = NULL;      		// RSA key initialized to NULL.
	FILE *fd = NULL;			// File.
	X509 *cert = NULL;     		// Certificate.
	EVP_PKEY *pkey = NULL; 		// Public key.
	// Open the file in binary read mode.
	fd = fopen(file, "rb");
	if (fd == NULL)
	{
		printf("Error al abrir el fichero '%s'.\n", file);
		return (NULL); 			// Return NULL in case of error.
	}
	// Read the certificate from file.
	cert = PEM_read_X509(fd, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("Error al leer el certificado desde el file '%s'.\n", file);
		fclose(fd); 			// Close the file.
		return (NULL);   		// Return NULL in case of error.
	}
    // Get public key of the certificate.
	pkey = X509_get_pubkey(cert);
	if (pkey == NULL)
	{
		printf("Error al obtener la clave pública desde el certificado.\n");
		fclose(fd); 			// Close the file.
		X509_free(cert); 		// Free the certificate.
		return (NULL);   		// Return NULL in case of error.
	}
    // Get RSA key from the public key.
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL)
	{
		printf("Error al obtener la clave RSA desde la clave pública.\n");
		fclose(fd);     		// Close the file.
		X509_free(cert);    	// Free the certificate.
		EVP_PKEY_free(pkey);	// Free public key.
		return (NULL);      	// Return NULL in case of error.
	}
	fclose(fd);					// Close the file and free memory.
	X509_free(cert);			// Free the memory allocated for an X.509 certificate object.
	EVP_PKEY_free(pkey);		// Freee the memory allocated for an EVP_PKEY.
	return (rsa);
}

int	main(int argc, char *argv[])
{
	unsigned char *res; 
	unsigned char *sol; 
	BN_CTX *ctx;        
	RSA *privada;       
	BIO *bioprint;      
	BIGNUM *one;        
	RSA *rsa1;          
	BIGNUM *n1;         
	BIGNUM *q1;         
	RSA *rsa2;          
	BIGNUM *n2;         
	BIGNUM *q2;         
	BIGNUM *p;           
	BIGNUM *total;      
	BIGNUM *fi1;        
	BIGNUM *fi2;        
	BIGNUM *e;          
	BIGNUM *d;          
	int fd;             
	int len;
	//These lines initialize all the variables to be used.
	if(argc != 4)
	{
		printf("Usage: ./corsair <cert1.pem> <cert2.pem>");
		return (0);
	}
	//These lines check the arguments.
	res = malloc(sizeof(unsigned char) * BUFFER);
    /* This line dynamically allocates memory for an array 
	of unsigned characters (unsigned char) called res. The 
	size of the array is specified as BUFFER and multiplied 
	by the size of an unsigned char in bytes using sizeof. 
	The malloc() function is a standard library function that 
	dynamically allocates memory at runtime. */
	sol = malloc(sizeof(unsigned char) * BUFFER);
 	/* This line dynamically allocates memory for another 
	array of unsigned characters called sol. */
	ctx = BN_CTX_new();
    /* This line creates a new bignum (big integer) context 
	using the BN_CTX_new() function. Bignums are integers that 
	can be much larger than what can typically be stored in 
	variables of type int or long in C. */
	bioprint = BIO_new_fp(stdout, BIO_NOCLOSE);
    /* This line creates a new bignum I/O object using the 
	BIO_new_fp() function with stdout as the output file and 
	BIO_NOCLOSE as the close flag. This means that the bioprint 
	object will be used to print the results to the screen. */
	rsa1 = get_rsa(argv[1]);
    /* This line calls a function called get_rsa() that takes 
	an argument argv[1] (the first command-line argument) and 
	returns an RSA public key object called rsa1. */
	rsa2 = get_rsa(argv[2]);
    /* This line calls the same function get_rsa() with the 
	second command-line argument (argv[2]) and returns another 
	RSA public key object called rsa2. */
	one = BN_new();
    /* This line creates a new bignum object called "one" and 
	initializes it to 1. */
	q1 = BN_new();
    /* This line creates another bignum object called q1 that 
	will be used to store one of the prime factors of rsa1. */
	q2 = BN_new();
    /* This line creates another bignum object called q2 that 
	will be used to store one of the prime factors of rsa2. */
	p = BN_new();
    /* This line creates another bignum object called "p" that 
	will be used to store the product of q1 and q2. */
	d = BN_new();
    /* This line creates another bignum object called "d" that 
	will be used to store the RSA private key. */
	total = BN_new();
    /* This line creates another bignum object called "total" 
	that will be used to store the total number of possible 
	private keys. */
	fi1 = BN_new();
    /* This line creates another bignum object called "fi1" that 
	will be used to store the value of the Euler's totient 
	function of q1. */
	fi2 = BN_new();
    /* This line creates another bignum object called "fi2" 
	that will be used to store the value of the Euler's totient 
	function of q2. */
	privada = RSA_new();
    /* This line creates a new RSA private key object called 
	"privada". This object will be used to store the RSA private 
	key calculated from the public keys rsa1 and rsa2. */

	n1 = (BIGNUM *)RSA_get0_n(rsa1);
    n2 = (BIGNUM *)RSA_get0_n(rsa2);
    e = (BIGNUM *)RSA_get0_e(rsa1);
    /* These lines extract the values of the modulus n and the 
	public exponent e from the public keys rsa1 and rsa2 using 
	the functions RSA_get0_n() and RSA_get0_e(). The extracted 
	values are stored in BIGNUM objects named n1, n2, and e 
	respectively. */
	BN_gcd(p, n1, n2, ctx);
    /* This line calculates the greatest common divisor (GCD) 
	of n1 and n2 using the BN_gcd() function. The result is 
	stored in the BIGNUM object named "p", which contains the 
	common prime factor. */
	BN_div(q1, NULL, n1, p, ctx);     
	BN_div(q2, NULL, n2, p, ctx);
    /* These lines use the BN_div() function to calculate the 
	prime factors q1 and q2 of the public keys rsa1 and rsa2, 
	respectively. p is the common prime factor that has already
	 been calculated earlier. The second argument NULL indicates 
	 that the remainder is not needed. */
	BN_dec2bn(&one, "1");             
	BN_sub(fi1, q1, one);             
	BN_sub(fi2, p, one);              
	BN_mul(total, fi1, fi2, ctx);
    /* These lines calculate the value of the Euler's totient 
	function of q1 and p, and then multiply the results to obtain 
	the total number of possible private keys. The BN_dec2bn() 
	function is used to initialize the BIGNUM object "one" with 
	the value 1. */
	BN_mod_inverse(d, e, total, ctx); 
    /* This line uses the BN_mod_inverse() function to calculate 
	the RSA private key using the public exponent e, the value of 
	the total Euler's totient function, and the context ctx. The 
	result is stored in the BIGNUM object named "d". */
	RSA_set0_key(privada, n1, e, d);
    /* This line sets the values of the modulus n, the public 
	exponent e, and the private key d in the private key object 
	"privada" using the RSA_set0_key() function. */
	RSA_set0_factors(rsa1, p, q1);
	RSA_set0_factors(rsa2, p, q2);
    /* These lines set the values of the prime factors p and q1 
	(for rsa1) and q2 (for rsa2) in the respective public keys 
	using the RSA_set0_factors() function. */
	fd = open(argv[3], O_RDONLY);
	/*This line opens the file specified in the third command-line argument 
	in read mode (O_RDONLY). The file descriptor is stored in the variable"fd".*/
	if (fd < 1)
	{
		printf("File not valid.");
		return (0);
	}
	/* Here we are checking that the file received as the third argument is valid.*/
	printf("\nCERTIFICADO 1:\n");
	RSA_print(bioprint, rsa1, 0);
	RSA_print(bioprint, privada, 0);
	printf("\nCERTIFICADO 2:\n");
	RSA_print(bioprint, rsa2, 0);
	RSA_print(bioprint, privada, 0);
    /* These lines print the obtained certificates to the screen. 
	First, the rsa1 certificate is printed along with the private 
	key "privada", and then the rsa2 certificate is printed with the 
	same private key. The RSA_print() function is used to print the public
	and private key objects. The second argument 0 indicates that no 
	additional format will be used.*/
	len = read(fd, res, BUFFER);
    /* This line uses the read() function to read up to BUFFER bytes 
	from the file opened in fd and stores them in the buffer "res". The 
	number of bytes read is stored in the variable "len". */
	RSA_private_decrypt(len, res, sol, privada, RSA_PKCS1_PADDING);
    /* This line uses the RSA_private_decrypt() function to decrypt the 
	data in the buffer "res" using the private key "privada". The result 
	is stored in the buffer "sol". "len" is the length of the encrypted 
	data in "res". RSA_PKCS1_PADDING is a flag that specifies the type of
	 padding used in the encryption. */
	printf("\nTexto encriptado:\n");
	printf("%s\n", res);
	printf("Texto desencriptado:\n");
	printf("%s\n", sol);
	//These lines print the encrypted and descrypted text.
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
	//These lines free all variables.
	return (0);
}
