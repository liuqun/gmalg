
#include <string.h>
#include "miracl.h"
#include "sm3.h"

#define SM2_WORDSIZE 8
#define SM2_NUMBITS 256
#define SM2_NUMWORD (SM2_NUMBITS/SM2_WORDSIZE) //32
#define ERR_ECURVE_INIT 0x00000001
#define ERR_NOT_VALID_POINT 0x00000003
#define ERR_ORDER 0x00000004
#define ERR_GENERATE_R 0x00000006
#define ERR_GENERATE_S 0x00000007
#define ERR_OUTRANGE_R 0x00000008
#define ERR_OUTRANGE_S 0x00000009
#define ERR_GENERATE_T 0x0000000A
#define ERR_PUBKEY_INIT 0x0000000B
#define ERR_DATA_MEMCMP 0x0000000C

#define ERR_INFINITY_POINT 0x00000001
#define ERR_NOT_VALID_ELEMENT 0x00000002
#define ERR_NOT_VALID_POINT 0x00000003
#define ERR_ORDER 0x00000004
#define ERR_ARRAY_NULL 0x00000005
#define ERR_C3_MATCH 0x00000006
#define ERR_SELFTEST_KG 0x00000008
#define ERR_SELFTEST_ENC 0x00000009
#define ERR_SELFTEST_DEC 0x0000000A


extern unsigned char SM2_p[32];
extern unsigned char SM2_a[32];
extern unsigned char SM2_b[32];
extern unsigned char SM2_Gx[32];
extern unsigned char SM2_Gy[32];
extern unsigned char SM2_n[32];

void SM3_KDF(unsigned char *Z ,unsigned short zlen,unsigned short klen,unsigned char *K);

extern epoint *G,*nG;
extern big para_p,para_a,para_b,para_n,para_Gx,para_Gy,para_h;
extern miracl *mip;

int SM2_Init();
int Test_Null(unsigned char array[],int len);
int Test_Point(epoint* point);
int Test_PubKey(epoint *pubKey);
int Test_Zero(big x);
int Test_n(big x);
int Test_Range(big x);

int SM2_Encrypt(unsigned char* randK,epoint *pubKey,unsigned char M[],int klen,unsigned char C[]);
int SM2_Decrypt(big dB,unsigned char C[],int Clen,unsigned char M[]);
int SM2_ENC_SelfTest();

int SM2_KeyGeneration_enc(big priKey,epoint *pubKey);
int SM2_KeyGeneration(unsigned char PriKey[],unsigned char Px[],unsigned char Py[]);
int SM2_Sign(unsigned char *message,int len,unsigned char ZA[],unsigned char rand[],unsigned char d[],unsigned char R[],unsigned char S[]);
int SM2_Verify(unsigned char *message,int len,unsigned char ZA[],unsigned char Px[],unsigned char Py[],unsigned char R[],unsigned char S[]);
int SM2_SelfCheck();
