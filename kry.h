/**
 * 	File: kry.h
 *	Course: KRY - Cryptography
 *	Project: 2. RSA
 *	Name: Tomas Bruckner, xbruck02@stud.fit.vutbr.cz
 *	Date: 2016-04-04
 *	Description:
 **/

/*
 *	Generates primes P and Q, public modulus N, public exponent E and private key D.
 *	@param bitlength specifies length of modulus in bits.
 */
void rsa_generate_key(const unsigned long bitlength);

/*
 *	Factorizes public modulus to mod = p*q. Set result to prime P.
 *	@param result output, prime P
 *	@param mod public modulus
 */
void rsa_break_key(mpz_t result, const mpz_t mod);

/*
 *	Generates random prime.
 *	@param result output, random prime
 *	@param bitlength length of prime in bits
 *	@param state initialiazed state with seed for random number generation
 */
void generate_prime(mpz_t result, const unsigned long bitlength, gmp_randstate_t state);

/*
 *	Finds greatest common divisor.
 *	@param result output, gcd for op1 and op2
 */
void gcd_euclid(mpz_t result, const mpz_t op1, const mpz_t op2);

/*
 *	Find multiplicative inverse for x mod n.
 *	@param result output, x^(-1)
 */
void inverse_extended_euclid(mpz_t result, const mpz_t n, const mpz_t x);

/*
 *	Associated function for inverse_extended_euclid function.
 */
void update(mpz_t a, mpz_t b, const mpz_t y);

/*
 *	Checks if n is a prime using Fermat's primality test.
 *	@param n number to be checked
 *	@param state initiliazed state with seed for random number generation
 *	@return TRUE if n is a prime, otherwise FALSE
 */
int fermat_test(const mpz_t n, gmp_randstate_t state);

/*
 *	Checks if n is a prime using Miller-Rabin's primality test.
 *	@param n number to be checked
 *	@param state initialized state with seed for random number generation
 *	@return TRUE if n is a prime, otherwise FALSE
 */
int miller_rabin_test(mpz_t n, gmp_randstate_t state);

/*
 *	Factorizes n to n = p*q using Pollard rho Brent's variant integer factorization algorithm.
 *	@param result output, prime p
 *	@param n number to be factorized
 */
void pollard_rho_brent(mpz_t result, const mpz_t n);

