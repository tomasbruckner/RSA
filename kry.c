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
#include <time.h>
#include <gmp.h>
#include "kry.h"

#define FALSE 0
#define TRUE 1

int main (int argc, char** argv){
	if(argc == 1) return 1;
	mpz_t result;	
	mpz_init(result);

    // generate
	if(strcmp(argv[1], "-g") == 0){ 
		rsa_generate_key( strtoul(argv[2], NULL, 0) );
    }
    // encrypt or decrypt
	else if( strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0 ){
		if(argc != 5) return 1;
		mpz_t exponent, text, mod;
		mpz_init_set_str(exponent, argv[2] + 2, 16);
		mpz_init_set_str(mod, argv[3] + 2, 16);
		mpz_init_set_str(text, argv[4] + 2, 16);
		
		mpz_powm(result, text, exponent, mod);
	    gmp_printf("%#Zx\n", result);
	}
    // break
	else if(strcmp(argv[1], "-b") == 0){
        mpz_t mod;
        mpz_init_set_str(mod, argv[2] + 2, 16);
        
		rsa_break_key(result, mod);
        mpz_clear(mod);
	    gmp_printf("%#Zx\n", result);
    }
	else return 1;

	return 0;
}

void rsa_break_key(mpz_t result, const mpz_t mod){
    // even
    if(mpz_even_p(mod) != 0){
        mpz_set_ui(result, 0x2);
        return;
    }

    // trial division
    for(int i = 0x3; i < 0xf4240; i = i + 2){
        if( mpz_mod_ui(result, mod, i) == 0){
            mpz_set_ui(result, i);
            return;
        }
    }

    pollard_rho_brent(result, mod);
}

void rsa_generate_key(const unsigned long bitlength){
    mpz_t p, q, phi_n, e, d, tmp;
    mpz_init(p);
    mpz_init(q);
    mpz_init(phi_n);
    mpz_init(e);
    mpz_init(tmp);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // even/odd check
    int offset = bitlength%2 == 0? 0 : 1;
    
    generate_prime(p, bitlength/2 + offset, state);
    generate_prime(q, bitlength/2, state);

	gmp_printf("%#Zx ", p);
	gmp_printf("%#Zx ", q);
    
    // public modulus N
    mpz_mul(tmp, p, q);
	gmp_printf("%#Zx ", tmp);

    // phi_n = (p-1)*(q-1)
    mpz_sub_ui(tmp, p, 0x1);
    mpz_sub_ui(phi_n, q, 0x1);
    mpz_mul(phi_n, phi_n, tmp);

    // Fermat's primes
    const int exponents[] = { 0x3, 0x5, 0x11, 0x101, 0x10001 };
    for(int i = 0; i < 5; i++){
        mpz_set_ui(e, exponents[i]);

        // private key d = e^(-1) mod phi_n
        inverse_extended_euclid(tmp, phi_n, e);
        if(mpz_cmp_ui(tmp, 0x1) != 0) break;
    }
    
    // public exponent E
	gmp_printf("%#Zx ", e);

    // private key D
	gmp_printf("%#Zx\n", tmp);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi_n);
    mpz_clear(e);
    mpz_clear(tmp);
    gmp_randclear(state);
}

// http://crypto.stackexchange.com/questions/1970/how-are-primes-generated-for-rsa
// http://crypto.stackexchange.com/questions/71/how-can-i-generate-large-prime-numbers-for-rsa
void generate_prime(mpz_t result, const unsigned long bitlength, gmp_randstate_t state){
    // generate random number greater 2
	do{
		mpz_urandomb(result, state, bitlength);
    }while( mpz_cmp_ui(result, 0x3) <= 0);

    // if random number is even, make it odd
    if(mpz_even_p(result) != 0) mpz_add_ui(result, result, 0x1);
    
    int isprime = FALSE;
    while(1){
        isprime = FALSE;
        if(fermat_test(result, state)){
            // one iteration has probability 1/2 of error
            for(int i = 0; i < 100; i++){
                if( !miller_rabin_test(result, state) ){
                    isprime = FALSE;
                    break;
                }
                isprime = TRUE;
            }
        }
        
        if(isprime) break;

        // if not prime, add 2
        mpz_add_ui(result, result, 0x2);
    }
}

// http://blog.janmr.com/2009/10/computing-the-greatest-common-divisor.html
void gcd_euclid(mpz_t result, const mpz_t op1, const mpz_t op2){
    mpz_t   tmp1,   // op1 clone
            tmp2;   // op2 clone
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

void inverse_extended_euclid(mpz_t result, const mpz_t n, const mpz_t x){
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
    
    // b = y*b - a
    mpz_set(tmp, b);
    mpz_mul(tmp2, y, tmp);
    mpz_sub(b, a, tmp2);

    // a = b
    mpz_set(a, tmp);

    mpz_clear(tmp);
    mpz_clear(tmp2);
}

// http://mathcircle.berkeley.edu/BMC5/docpspdf/is-prime.pdf
int fermat_test(const mpz_t n, gmp_randstate_t state){
    int isprime = FALSE;
    mpz_t tmp, a, n_1;
    mpz_init(tmp);
    mpz_init(a);
    mpz_init(n_1);
    mpz_sub_ui(n_1, n, 0x1);

    // generate a random a in {2,..., n-1}
    do{
        mpz_urandomm(a, state, n);
    }while(mpz_cmp_ui(a, 0x2) < 0);

    // tmp = gcd(a, n)
    gcd_euclid(tmp, a, n);
    if(mpz_cmp_ui(tmp, 1) > 0){
        isprime = FALSE;
    }
    else{    
        // tmp = a^(n-1) mod n
	    mpz_powm(tmp, a, n_1, n);
        isprime = mpz_cmp_ui(tmp, 0x1) == 0? TRUE: FALSE;
    }

    mpz_clear(tmp);
    mpz_clear(a);
    mpz_clear(n_1);

    return isprime;
}

// http://mathcircle.berkeley.edu/BMC5/docpspdf/is-prime.pdf
int miller_rabin_test(mpz_t n, gmp_randstate_t state){
    int isprime = FALSE;
    mpz_t m, a, b, n_1, tmp;
    mpz_init(a);
    mpz_init(b);
    mpz_init(m);
    mpz_init(tmp);
    mpz_init(n_1);
    mpz_sub_ui(n_1, n, 0x1);
    
    // generate a random a in {2,..., n-1}
    do{
        mpz_urandomm(a, state, n);
    }while(mpz_cmp_ui(a, 0x2) < 0);

    // m = n-1
    mpz_set(m, n_1);   

    int t = 0;

    // factor n-1 as m*2^t 
    while(mpz_even_p(m) != 0){
        mpz_fdiv_q_2exp(m, m, 1);
        t++;
    }
    
    // b = a^m mod n
    mpz_powm(b, a, m, n);

    // b == 1 then prime
    if(mpz_cmp_ui(b, 0x1) == 0) isprime = TRUE;

    // b == -1 then prime
    // can be written as mpz_cmp(b, n_1); but is 50x slower
    mpz_sub(tmp, b, n);
    if(mpz_cmp_si(tmp, -1) == 0) isprime = TRUE;

    if(!isprime){
        for(int i = t - 1; i != 0; i--){
            mpz_powm_ui(b, b, 0x2, n);
            
            // b == 1 then composite
            if(mpz_cmp_ui(b, 0x1) == 0){
                break;
            }

            // b == -1 then prime
            mpz_sub(tmp, b, n);
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

void pollard_rho_brent(mpz_t result, const mpz_t n){
    // check if even
    if(mpz_even_p(n) != 0){
        mpz_set_ui(result, 0x2);
        return;
    }

    mpz_t y, c, m, g, r, q, k, n_1, x, ys, i, j, len, tmp;
    mpz_init(y);
    mpz_init(c);
    mpz_init(m);
    mpz_init(g);
    mpz_init(r);
    mpz_init(q);
    mpz_init(k);
    mpz_init(x);
    mpz_init(i);
    mpz_init(j);
    mpz_init(ys);
    mpz_init(len);
    mpz_init(tmp);

    mpz_init(n_1);
    mpz_sub_ui(n_1, n, 0x1);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // generate random y in {1,...,n-1}
    mpz_urandomm(y, state, n_1);
    mpz_add_ui(y, y, 0x1);

    // generate random c in {1,...,n-1}
    mpz_urandomm(c, state, n_1);
    mpz_add_ui(c, c, 0x1);

    // generate random m in {1,...,n-1}
    mpz_urandomm(m, state, n_1);
    mpz_add_ui(m, m, 0x1);

    mpz_set_ui(g, 0x1);
    mpz_set_ui(r, 0x1);
    mpz_set_ui(q, 0x1);

    while(mpz_cmp_ui(g, 0x1) == 0){
        mpz_set(x, y);
        
        // for (i = 0; i < r; i++)
        for(mpz_set_ui(i, 0x0); mpz_cmp(i, r) < 0; mpz_add_ui(i, i, 0x1)){
            // y = (y*y mod n + c) mod n
            mpz_mul(y, y, y);
            mpz_mod(y, y, n);
            mpz_add(y, y, c);
            mpz_mod(y, y, n);
        }

        mpz_set_ui(k, 0x0);

        // while(k<r && g == 1)
        while(mpz_cmp(k, r) < 0 && mpz_cmp_ui(g, 0x1) == 0){
            mpz_set(ys, y);

            // len = min(m, r-k)
            mpz_sub(tmp, r, k);
            if(mpz_cmp(m, tmp) < 0){
                mpz_set(len, m);
            }
            else{
                mpz_set(len, tmp);
            }

            // for(j=0; j < len; j++)
            for(mpz_set_ui(j, 0x0); mpz_cmp(j, len) < 0; mpz_add_ui(j, j, 0x1)){
                // y = (y*y mod n + c) mod n
                mpz_mul(y, y, y);
                mpz_mod(y, y, n);
                mpz_add(y, y, c);
                mpz_mod(y, y, n);
                
                // q = abs(x-y)*q mod n
                mpz_sub(tmp, x, y);
                mpz_abs(tmp, tmp);
                mpz_mul(q, q, tmp);
                mpz_mod(q, q, n);
            }

            gcd_euclid(g, q, n);
    
            mpz_add(k, k, m);
        }
        mpz_mul_ui(r, r, 0x2);
    }    

    if(mpz_cmp(g, n) == 0){
        while(1){
            // ys = (ys*ys mod n + c) mod n
            mpz_mul(ys, ys, ys);
            mpz_mod(ys, ys, n);
            mpz_add(ys, ys, c);
            mpz_mod(ys, ys, n);

            // g = abs(x-ys)
            mpz_sub(g, x, ys);
            mpz_abs(g, g);

            gcd_euclid(g, g, n);

            if(mpz_cmp_ui(g, 0x1) > 0) break;
        }
    }

    mpz_set(result, g);

    mpz_clear(y);
    mpz_clear(c);
    mpz_clear(m);
    mpz_clear(g);
    mpz_clear(r);
    mpz_clear(q);
    mpz_clear(k);
    mpz_clear(x);
    mpz_clear(ys);
    mpz_clear(i);
    mpz_clear(j);
    mpz_clear(len);
    mpz_clear(tmp);

    gmp_randclear(state);
}

// vim: expandtab:shiftwidth=4:tabstop=4:softtabstop=0:textwidth=120

