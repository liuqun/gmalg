#include "miracl.h"
#include "mirdef.h"

#define ERR_INFINITY_POINT 0x00000001
#define ERR_NOT_VALID_ELEMENT 0x00000002
#define ERR_NOT_VALID_POINT 0x00000003
#define ERR_ORDER 0x00000004
#define ERR_KEYEX_RA 0x00000006
#define ERR_KEYEX_RB 0x00000007
#define ERR_EQUAL_S1SB 0x00000008
#define ERR_EQUAL_S2SA 0x00000009
#define ERR_SELFTEST_Z 0x0000000A
#define ERR_SELFTEST_INI_I 0x0000000B
#define ERR_SELFTEST_RES_I 0x0000000C
#define ERR_SELFTEST_INI_II 0x0000000D

int SM2_W(big n);
void SM3_Z(unsigned char ID[], unsigned short int ELAN, epoint* pubKey, unsigned char hash[]);

int SM2_KeyEx_Init_I(big ra, epoint* RA);
int SM2_KeyEx_Re_I(big rb, big dB, epoint* RA, epoint* PA, unsigned char ZA[],unsigned char ZB[],
		unsigned char K[],int klen,epoint* RB, epoint* V,unsigned char hash[]);
int SM2_KeyEx_Init_II(big ra, big dA, epoint* RA,epoint* RB, epoint* PB, unsigned char ZA[],
		unsigned char ZB[],unsigned char SB[],unsigned char K[],int klen,unsigned char SA[]);
int SM2_KeyEx_Re_II(epoint *V,epoint *RA,epoint *RB,unsigned char ZA[],unsigned char ZB[],unsigned char SA[]);
int SM2_KeyEx_SelfTest();
