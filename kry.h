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

void rsa_generate_key(mpz_t result, const unsigned long bit);

void rsa_break_key(mpz_t result, mpz_t mod);

void generate_prime(mpz_t result, const unsigned long bit);

void gcd_euclid(mpz_t result, const mpz_t op1, const mpz_t op2);

void inverse_extended_euclid(mpz_t result, mpz_t n, mpz_t x);

void update(mpz_t a, mpz_t b, const mpz_t y);

int fermat_test(const mpz_t prime);

int miller_rabin_test(mpz_t prime);
