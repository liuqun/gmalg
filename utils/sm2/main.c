
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int SM2_ENC_SelfTest();
extern int SM2_SelfCheck();
extern int SM3_SelfTest();

int main()
{
	SM2_ENC_SelfTest();
	SM2_SelfCheck();
	SM3_SelfTest();
	return 0;
}
