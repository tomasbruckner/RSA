/**
 * 	File: kry.h
 *	Course: KRY - Cryptography
 *	Project: 2. RSA
 *	Name: Tomas Bruckner, xbruck02@stud.fit.vutbr.cz
 *	Date: 2016-04-04
 *	Description:
 **/

void my_invert(mpz_t result, mpz_t value, mpz_t mod);

void rsa_decrypt(mpz_t result, mpz_t exponent, mpz_t mod, mpz_t ciphertext);

void rsa_encrypt(mpz_t result, mpz_t exponent, mpz_t mod, mpz_t message);

void rsa_generate_key(mpz_t result, int mod_length);

void rsa_break_key(mpz_t result, mpz_t mod);

