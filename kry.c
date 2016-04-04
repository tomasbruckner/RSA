/**
 * 	File: kry.c
 *	Course: KRY - Cryptography
 *	Project: 2. RSA
 *	Name: Tomas Bruckner, xbruck02@stud.fit.vutbr.cz
 *	Date: 2016-04-04
 *	Description:
 **/

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include "kry.h"

int main (int argc, char** argv){
	if(argc == 1) return 1;
	mpz_t result;	
	mpz_init(result);
	if(strcmp(argv[1], "-g") == 0) ;
		//rsa_generate_key(result, argv[2]);
	else if(strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0){
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

