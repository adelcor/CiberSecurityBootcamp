#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

int main(int argc, char **argv)
{
	BIO *BIO;
	X509 *X509;
	EVP_PKEY *pubkey;
	RSA *RSA;

	BIO = BIO_new_file(argv[1], "r");
 
	X509 = PEM_read_bio_X509(BIO, NULL, NULL, NULL);

	pubkey  = X509_get_pubkey(X509);	

	RSA =	EVP_PKEY_get1_RSA(pubkey);





	



	
	return (0);
}
