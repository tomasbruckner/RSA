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
	if(strcmp(argv[1], "-g") == 0) 
		rsa_generate_key( result, strtoul(argv[2], NULL, 10) );
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

void rsa_generate_key(mpz_t result, unsigned long bit){
	
}

void generate_prime(mpz_t result, unsigned long bit){
	do{
		gmp_randstate_t state;
		gmp_randinit_default(state);
		mpz_urandomb(result, state, bit);
    }while( mpz_cmp_ui(result, 3) <= 0);

    if(mpz_even_p(result) != 0) mpz_add_ui(result, result, 1);
}

// http://blog.janmr.com/2009/10/computing-the-greatest-common-divisor.html
void gcd_euclid(mpz_t result, mpz_t op1, mpz_t op2){
    while(1){
        if(mpz_sgn(op2) == 0){
            mpz_set(result, op1);
            return;
        }
        mpz_mod(op1, op1, op2);
        if(mpz_sgn(op1) == 0){
            mpz_set(result, op2);
            return;
        }
        mpz_mod(op2, op2, op1);
    }
}

// http://mathcircle.berkeley.edu/BMC5/docpspdf/is-prime.pdf
int fermat_test(mpz_t prime){
    int isprime = FALSE;
    mpz_t tmp, a, n_1;
    mpz_init(tmp);
    mpz_init(a);
    mpz_init(n_1);
    mpz_sub_ui(n_1, prime, 1);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(a, state, n_1);
    
    gcd_euclid(tmp, a, prime);
    if(mpz_cmp_ui(tmp, 1) > 0) isprime = FALSE;
    
	mpz_powm(tmp, a, n_1, prime);
    isprime = mpz_cmp_ui(tmp, 1) == 0? TRUE: FALSE;

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
    mpz_sub_ui(n_1, prime, 1);
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

