/**
 *	File: kry.c
 *	Course: KRY - Cryptography
 *	Project: 2. RSA
 *	Name: Tomas Bruckner, xbruck02@stud.fit.vutbr.cz
 *	Date: 2016-04-04
 *	Description:
 **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "kry.h"

#define FALSE 0
#define TRUE 1

int main (int argc, char** argv){
	if(argc == 1) return 1;
	mpz_t result;	
	mpz_init(result);

	if(strcmp(argv[1], "-g") == 0){ 
		rsa_generate_key( result, 10 );
    }
	else if( strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0 ){
		if(argc != 5) return 1;
		mpz_t exponent, text, mod;
		mpz_init_set_str(exponent, argv[2] + 2, 16);
		mpz_init_set_str(mod, argv[3] + 2, 16);
		mpz_init_set_str(text, argv[4] + 2, 16);
		
		mpz_powm(result, text, exponent, mod);
		
	} 
	else if(strcmp(argv[1], "-b") == 0) ;
		//rsa_break_key(result, mod);
	else return 1;

	gmp_printf("%#Zx\n", result);
	return 0;
}

void rsa_generate_key(mpz_t result, const unsigned long bit){
    mpz_t p, q, phi_n, e, d, tmp;
    mpz_init(p);
    mpz_init(q);
    mpz_init(phi_n);
    mpz_init(e);
    mpz_init(tmp);
    generate_prime(p, bit/2);
    generate_prime(q, bit/2);

    mpz_sub_ui(tmp, p, 0x1);
    mpz_sub_ui(phi_n, q, 0x1);
    mpz_mul(phi_n, phi_n, tmp);

    mpz_set_ui(e, 0x3);
    
    inverse_extended_euclid(result, phi_n, e);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi_n);
    mpz_clear(e);
    mpz_clear(tmp);
}

// http://crypto.stackexchange.com/questions/1970/how-are-primes-generated-for-rsa
// http://crypto.stackexchange.com/questions/71/how-can-i-generate-large-prime-numbers-for-rsa
void generate_prime(mpz_t result, const unsigned long bit){
	do{
		gmp_randstate_t state;
		gmp_randinit_default(state);
		mpz_urandomb(result, state, bit);
    }while( mpz_cmp_ui(result, 0x3) <= 0);

    if(mpz_even_p(result) != 0) mpz_add_ui(result, result, 0x1);

    while(1){
        if( fermat_test(result) ){
            if( miller_rabin_test(result) ){
                break;
            }
        }
        
        mpz_add_ui(result, result, 0x2);
    }
}

// http://blog.janmr.com/2009/10/computing-the-greatest-common-divisor.html
void gcd_euclid(mpz_t result, const mpz_t op1, const mpz_t op2){
    mpz_t tmp1, tmp2;
    mpz_init(tmp1);
    mpz_init(tmp2);
    mpz_set(tmp1, op1);
    mpz_set(tmp2, op2);

    while(1){
        if(mpz_sgn(tmp2) == 0){
            mpz_set(result, tmp1);
            break;
        }
        mpz_mod(tmp1, tmp1, tmp2);
        if(mpz_sgn(tmp1) == 0){
            mpz_set(result, tmp2);
            break;
        }
        mpz_mod(tmp2, tmp2, tmp1);
    }

    mpz_clear(tmp1);
    mpz_clear(tmp2);
}

void inverse_extended_euclid(mpz_t result, mpz_t n, mpz_t x){
    mpz_t g, h, w, z, v, r, y;
    mpz_init(g);
    mpz_init(h);
    mpz_init(w);
    mpz_init(z);
    mpz_init(v);
    mpz_init(r);
    mpz_init(y);

    mpz_set(g, n);
    mpz_set(h, x);
    mpz_set_ui(w, 0x1);
    mpz_set_ui(z, 0x0);
    mpz_set_ui(v, 0x0);
    mpz_set_ui(r, 0x1);

    while(mpz_cmp_ui(h, 0x0) > 0){
        mpz_fdiv_q(y, g, h);
        update(g, h, y);
        update(w, z, y);
        update(v, r, y);
    }

    mpz_mod(result, v, n);

    mpz_clear(g);
    mpz_clear(h);
    mpz_clear(w);
    mpz_clear(z);
    mpz_clear(v);
    mpz_clear(r);
    mpz_clear(y);
}

void update(mpz_t a, mpz_t b, const mpz_t y){
    mpz_t tmp, tmp2;
    mpz_init(tmp);
    mpz_init(tmp2);
    
    mpz_set(tmp, b);

    mpz_mul(tmp2, y, tmp);
    mpz_sub(b, a, tmp2);

    mpz_set(a, tmp);

    mpz_clear(tmp);
    mpz_clear(tmp2);
}

// http://mathcircle.berkeley.edu/BMC5/docpspdf/is-prime.pdf
int fermat_test(const mpz_t prime){
    int isprime = FALSE;
    mpz_t tmp, a, n_1;
    mpz_init(tmp);
    mpz_init(a);
    mpz_init(n_1);
    mpz_sub_ui(n_1, prime, 0x1);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(a, state, n_1);
    gcd_euclid(tmp, a, prime);
    if(mpz_cmp_ui(tmp, 1) > 0) isprime = FALSE;
    
	mpz_powm(tmp, a, n_1, prime);
    isprime = mpz_cmp_ui(tmp, 0x1) == 0? TRUE: FALSE;

    mpz_clear(tmp);
    mpz_clear(a);
    mpz_clear(n_1);

    return isprime;
}

// http://mathcircle.berkeley.edu/BMC5/docpspdf/is-prime.pdf
int miller_rabin_test(mpz_t prime){
    int isprime = FALSE, t = 0;
    mpz_t m, a, b, n_1, tmp;
    mpz_init(a);
    mpz_init(b);
    mpz_init(m);
    mpz_init(tmp);
    mpz_init(n_1);
    mpz_sub_ui(n_1, prime, 0x1);
    gmp_randstate_t state;
    gmp_randinit_default(state);

    do{
        mpz_urandomm(a, state, n_1);
    }while(mpz_cmp_ui(a, 2) >= 0);

    mpz_set(m, n_1);   
    while(mpz_even_p(m) != 0){
        mpz_fdiv_q_2exp(m, m, 1);
        t++;
    }
    mpz_powm(b, a, m, prime);
    if(mpz_cmp_ui(b, 1) == 0) isprime = TRUE;
    mpz_sub(tmp, b, prime);
    if(mpz_cmp_si(tmp, -1) == 0) isprime = TRUE;

    if(!isprime){
        for(int i = t - 1; i != 0; i--){
            mpz_powm_ui(b, b, 2, prime);
            if(mpz_cmp_ui(b, 1) == 0){
                break;
            }
            mpz_sub(tmp, b, prime);
            if(mpz_cmp_si(tmp, -1) == 0){
                isprime = TRUE;
                break;
            } 
        }
    }

    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(m);
    mpz_clear(tmp);
    mpz_clear(n_1);
    return isprime;
}

// vim: expandtab:shiftwidth=4:tabstop=4:softtabstop=0:textwidth=120

