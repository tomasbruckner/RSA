/**
 *	Course: KRY - Cryptography
 *	Project: 2. RSA
 *	Name: Tomas Bruckner, xbruck02@stud.fit.vutbr.cz
 *	Date: 2016-04-04
 *	Description:
 **/

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

int main (){
	mpz_t fp, a, b, x, y, x_p, y_p, s, tmp, tmp2, x2, y2;

 	mpz_init_set_str(fp, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
	mpz_init_set_str(a, "-3", 16);
	mpz_init_set_str(b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
	mpz_init_set_str(x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
	mpz_init_set_str(y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

	mpz_init_set_str(x_p, "52910a011565810be90d03a299cb55851bab33236b7459b21db82b9f5c1874fe", 16);
	mpz_init_set_str(y_p, "e3d03339f660528d511c2b1865bcdfd105490ffc4c597233dd2b2504ca42a562", 16);

	mpz_init(s);
	mpz_init(tmp);
	mpz_init(tmp2);
	mpz_init(x2);
	mpz_init(y2);

	//s = ((3*x*x + a) / (2*y)) % fp
	mpz_mul(tmp, x, x);
	mpz_mul_ui(tmp, tmp, 3);
	mpz_add(tmp, tmp, a);
	mpz_mul_ui(tmp2, y, 2);
	mpz_invert(tmp2, tmp2, fp);
	mpz_mul(tmp, tmp, tmp2);
	mpz_mod(s, tmp, fp);

	//x2 = (s*s - 2*x) % fp
	mpz_mul(tmp, s, s);
	mpz_mul_ui(tmp2,x,2);
	mpz_sub(tmp, tmp, tmp2);
	mpz_mod(x2, tmp, fp);

	//y2 = (s*(x - x2 ) - y) % fp
	mpz_sub(tmp, x, x2);
	mpz_mul(tmp, s, tmp);
	mpz_sub(tmp, tmp, y);
	mpz_mod(y2, tmp, fp);

	//gmp_printf("%#Zx\n", x2);
	//gmp_printf("%#Zx\n", y2);

	///////////
	int c = 2;
	for(;;){
		c++;
		//s = ((y - y2) / (x - x2)) % fp
  		mpz_sub(tmp, y, y2);
		mpz_sub(tmp2, x, x2);
		mpz_invert(tmp2, tmp2, fp);
		mpz_mul(tmp, tmp, tmp2);
		mpz_mod(s, tmp, fp);
	
		//x2 = (s*s - x - x2) % fp
 		mpz_mul(tmp, s, s);
		mpz_sub(tmp, tmp, x);
		mpz_sub(tmp, tmp, x2);
		mpz_mod(x2, tmp, fp);		

		//y2 = (s*(x - x2) - y) % fp
		mpz_sub(tmp, x, x2);
		mpz_mul(tmp, s, tmp);
		mpz_sub(tmp, tmp, y);
		mpz_mod(y2, tmp, fp);
		if(!mpz_cmp(x_p, x2) && !mpz_cmp(y_p, y2)) {
			printf("%d\n", c);
			break;
		}
		//gmp_printf("%#Zx\n", x2);
		//gmp_printf("%#Zx\n", y2);
	}
	
	return 0;
}

