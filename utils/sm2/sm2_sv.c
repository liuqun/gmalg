
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kdf.h"

unsigned char SM2_p[32] =
{0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff};

unsigned char SM2_a[32] =
{0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xfc};

unsigned char SM2_b[32] = {0x28,0xe9,0xfa,0x9e, 0x9d,0x9f,0x5e,0x34,
0x4d,0x5a,0x9e,0x4b,0xcf,0x65,0x09,0xa7,
0xf3,0x97,0x89,0xf5, 0x15,0xab,0x8f,0x92, 0xdd,0xbc,0xbd,0x41,0x4d,0x94,0x0e,0x93};

unsigned char SM2_Gx[32]={0x32,0xc4,0xae,0x2c,
0x1f,0x19,0x81,0x19,0x5f,0x99,0x04,0x46,0x6a,0x39,0xc9,0x94,
0x8f,0xe3,0x0b,0xbf,0xf2,0x66,0x0b,0xe1,0x71,0x5a,0x45,0x89,0x33,0x4c,0x74,0xc7};

unsigned char
SM2_Gy[32]={0xbc,0x37,0x36,0xa2,0xf4,0xf6,0x77,0x9c,0x59,0xbd,0xce,0xe3,0x6b,0x69,0x21,0x53,0xd0,
0xa9,0x87,0x7c,0xc6,0x2a,0x47,0x40,0x02,0xdf,0x32,0xe5,0x21,0x39,0xf0,0xa0};

unsigned char SM2_n[32] =
{0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0x72,0x03,0xdf,0x6b,0x21,0xc6,0x05,0x2b,0x53,0xbb,0xf4,0x09,0x39,0xd5,0x41,0x23};

unsigned char SM2_h[32]=
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};

big para_p,para_a,para_b,para_n,para_Gx,para_Gy,para_h;
epoint *G,*nG;
miracl *mip;

int SM2_Init(){
	para_Gx=mirvar(0);
	para_Gy=mirvar(0);
	para_p=mirvar(0);
	para_a=mirvar(0);
	para_b=mirvar(0);
	para_n=mirvar(0);
	para_h=mirvar(0);
	bytes_to_big(SM2_NUMWORD,SM2_Gx,para_Gx);
	bytes_to_big(SM2_NUMWORD,SM2_Gy,para_Gy);
	bytes_to_big(SM2_NUMWORD,SM2_p,para_p);
	bytes_to_big(SM2_NUMWORD,SM2_a,para_a);
	bytes_to_big(SM2_NUMWORD,SM2_b,para_b);
	bytes_to_big(SM2_NUMWORD,SM2_n,para_n);
	bytes_to_big(SM2_NUMWORD,SM2_h,para_h);
	ecurve_init(para_a,para_b,para_p,MR_PROJECTIVE);
	G=epoint_init();
	nG=epoint_init();
	if (!epoint_set(para_Gx,para_Gy,0,G))//initialise point G
	{
		return ERR_ECURVE_INIT;
	}
	ecurve_mult(para_n,G,nG);
	if (!point_at_infinity(nG)) //test if the order of the point is n
	{
		return ERR_ORDER;
	}
	return 0;
}

int Test_Point(epoint* point)
{
	big x,y,x_3,tmp;
	x=mirvar(0);
	y=mirvar(0);
	x_3=mirvar(0);
	tmp=mirvar(0);
	//test if y^2=x^3+ax+b
	epoint_get(point,x,y);
	power (x, 3, para_p, x_3); //x_3=x^3 mod p
	multiply (x, para_a,x); //x=a*x
	divide (x, para_p, tmp); //x=a*x mod p , tmp=a*x/p
	add(x_3,x,x); //x=x^3+ax
	add(x,para_b,x); //x=x^3+ax+b
	divide(x,para_p,tmp); //x=x^3+ax+b mod p
	power (y, 2, para_p, y); //y=y^2 mod p
	if(mr_compare(x,y)!=0)
		return ERR_NOT_VALID_POINT;
	else
		return 0;
}

int Test_PubKey(epoint *pubKey)
{
	big x,y,x_3,tmp;epoint *nP;
	x=mirvar(0);
	y=mirvar(0);
	x_3=mirvar(0);
	tmp=mirvar(0);
	nP=epoint_init();
	//test if the pubKey is the point at infinity
	if (point_at_infinity(pubKey))// if pubKey is point at infinity, return error;
	return ERR_INFINITY_POINT;
	//test if x<p and y<p both hold
	epoint_get(pubKey,x,y);
	if((mr_compare(x,para_p)!=-1) || (mr_compare(y,para_p)!=-1))
		return ERR_NOT_VALID_ELEMENT;
	if(Test_Point(pubKey)!=0)
		return ERR_NOT_VALID_POINT;
	//test if the order of pubKey is equal to n
	ecurve_mult(para_n,pubKey,nP); // nP=[n]P
	if (!point_at_infinity(nP)) // if np is point NOT at infinity, return error;
	return ERR_ORDER;
	return 0;
}

int Test_Zero(big x)
{
	big zero;
	zero=mirvar(0);
	if(mr_compare(x,zero)==0)return 1;
	else return 0;
}

int Test_n(big x)
{
	// bytes_to_big(32,SM2_n,n);
	if(mr_compare(x,para_n)==0)
		return 1;
	else return 0;
}

int Test_Range(big x)
{
	big one,decr_n;
	one=mirvar(0);
	decr_n=mirvar(0);
	convert(1,one);
	decr(para_n,1,decr_n);
	if( (mr_compare(x,one) < 0)| (mr_compare(x,decr_n)>0) )
		return 1;
	return 0;
}

int Test_Null(unsigned char array[],int len)
{
	int i=0;
	for(i=0;i<len;i++)
	{
		if (array[i]!=0x00)
			return 0;
	}
	return 1;
}

int SM2_KeyGeneration(unsigned char PriKey[],unsigned char Px[],unsigned char Py[])
{
	int i=0;
	big d,PAx,PAy;
	epoint *PA;
	SM2_Init();
	PA=epoint_init();
	d=mirvar(0);
	PAx=mirvar(0);
	PAy=mirvar(0);
	bytes_to_big(SM2_NUMWORD,PriKey,d);
	ecurve_mult(d,G,PA);
	epoint_get(PA,PAx,PAy);
	big_to_bytes(SM2_NUMWORD,PAx,Px,TRUE);
	big_to_bytes(SM2_NUMWORD,PAy,Py,TRUE);
	i=Test_PubKey(PA);
	if(i)
		return i;
	else
		return 0;
}

int SM2_Sign(unsigned char *message,int len,unsigned char ZA[],unsigned char rand[],unsigned
		char d[],unsigned char R[],unsigned char S[])
{
	unsigned char hash[SM3_len/8];
	int M_len=len+SM3_len/8;
	unsigned char *M=NULL;
	int i;

	big dA,r,s,e,k,KGx,KGy;
	big rem,rk,z1,z2;
	epoint *KG;

	i=SM2_Init();
	if(i) 
		return i;//initiate

	dA=mirvar(0);
	e=mirvar(0);
	k=mirvar(0);
	KGx=mirvar(0);
	KGy=mirvar(0);
	r=mirvar(0);
	s=mirvar(0);
	rem=mirvar(0);
	rk=mirvar(0);
	z1=mirvar(0);
	z2=mirvar(0);
	bytes_to_big(SM2_NUMWORD,d,dA);//cinstr(dA,d);
	KG=epoint_init();
	//step1,set M=ZA||M
	M=(char *)malloc(sizeof(char)*(M_len+1));
	memcpy(M,ZA,SM3_len/8);
	memcpy(M+SM3_len/8,message,len);
	//step2,generate e=H(M)
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len/8,hash,e);
	//step3:generate k
	bytes_to_big(SM3_len/8,rand,k);
	//step4:calculate kG
	ecurve_mult(k,G,KG);
	//step5:calculate r
	epoint_get(KG,KGx,KGy);
	add(e,KGx,r);
	divide(r,para_n,rem);
	//judge r=0 or n+k=n?
	add(r,k,rk);
	if( Test_Zero(r) | Test_n(rk))
		return ERR_GENERATE_R;
	//step6:generate s
	incr(dA,1,z1);xgcd(z1,para_n,z1,z1,z1);
	multiply(r,dA,z2);
	divide(z2,para_n,rem);
	subtract(k,z2,z2);
	add(z2,para_n,z2);
	multiply(z1,z2,s);
	divide(s,para_n,rem);
	//judge s=0?
	if(Test_Zero(s))
		return ERR_GENERATE_S ;
	big_to_bytes(SM2_NUMWORD,r,R,TRUE);
	big_to_bytes(SM2_NUMWORD,s,S,TRUE);
	free(M);
	return 0;
}

int SM2_Verify(unsigned char *message,int len,unsigned char ZA[],unsigned char Px[],unsigned
		char Py[],unsigned char R[],unsigned char S[]){
	unsigned char hash[SM3_len/8];
	int M_len=len+SM3_len/8;
	unsigned char *M=NULL;
	int i;
	big PAx,PAy,r,s,e,t,rem,x1,y1;
	big RR;
	epoint *PA,*sG,*tPA;
	i=SM2_Init();
	if(i) return i;
	PAx=mirvar(0);
	PAy=mirvar(0);
	r=mirvar(0);
	s=mirvar(0);
	e=mirvar(0);
	t=mirvar(0);
	x1=mirvar(0);
	y1=mirvar(0);
	rem=mirvar(0);
	RR=mirvar(0);
	PA=epoint_init();
	sG=epoint_init();
	tPA=epoint_init();
	bytes_to_big(SM2_NUMWORD,Px,PAx);
	bytes_to_big(SM2_NUMWORD,Py,PAy);
	bytes_to_big(SM2_NUMWORD,R,r);
	bytes_to_big(SM2_NUMWORD,S,s);
	if (!epoint_set(PAx,PAy,0,PA))//initialise public key
	{
		return ERR_PUBKEY_INIT;
	}
	//step1: test if r belong to [1,n-1]
	if (Test_Range(r))
		return ERR_OUTRANGE_R;
	//step2: test if s belong to [1,n-1]
	if (Test_Range(s))
		return ERR_OUTRANGE_S;
	//step3,generate M
	M=(char *)malloc(sizeof(char)*(M_len+1));
	memcpy(M,ZA,SM3_len/8);
	memcpy(M+SM3_len/8,message,len);
	//step4,generate e=H(M)
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len/8,hash,e);
	//step5:generate t
	add(r,s,t);
	divide(t,para_n,rem);
	if( Test_Zero(t))
		return ERR_GENERATE_T;
	//step 6: generate(x1,y1)
	ecurve_mult(s,G,sG);
	ecurve_mult(t,PA,tPA);
	ecurve_add(sG,tPA);
	epoint_get(tPA,x1,y1);
	//step7:generate RR
	add(e,x1,RR);
	divide(RR,para_n,rem);
	free(M);
	if(mr_compare(RR,r)==0)
		return 0;
	else
		return ERR_DATA_MEMCMP;
}

int SM2_SelfCheck()
{
	int i;
	//the private key
	unsigned char dA[32]={
		0x39,0x45,0x20,0x8f,0x7b,0x21,0x44,0xb1,0x3f,0x36,0xe3,0x8a,0xc6,0xd3,0x9f,0x95,
		0x88,0x93,0x93,0x69,0x28,0x60,0xb5,0x1a,0x42,0xfb,0x81,0xef,0x4d,0xf7,0xc5,0xb8};

	unsigned char rand[32]={
		0x59,0x27,0x6E,0x27,0xD5,0x06,0x86,0x1A,0x16,0x68,0x0F,0x3A,0xD9,0xC0,0x2D,0xCC,
		0xEF,0x3C,0xC1,0xFA,0x3C,0xDB,0xE4,0xCE,0x6D,0x54,0xB8,0x0D,0xEA,0xC1,0xBC,0x21};

	//the public key
	unsigned char xA[32]={
		   0x09,0xf9,0xdf,0x31,0x1e,0x54,0x21,0xa1,0x50,0xdd,0x7d,0x16,0x1e,0x4b,0xc5,0xc6,
		   0x72,0x17,0x9f,0xad,0x18,0x33,0xfc,0x07,0x6b,0xb0,0x8f,0xf3,0x56,0xf3,0x50,0x20};
	unsigned char yA[32]={
	  	 0xcc,0xea,0x49,0x0c,0xe2,0x67,0x75,0xa5,0x2d,0xc6,0xea,0x71,0x8c,0xc1,0xaa,0x60,
	   	0x0a,0xed,0x05,0xfb,0xf3,0x5e,0x08,0x4a,0x66,0x32,0xf6,0x07,0x2d,0xa9,0xad,0x13};

	unsigned char r[32],s[32];// Signature
	unsigned char IDA[16]={
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};

	int IDA_len=16;
	unsigned char ENTLA[2]={0x00,0x80};//the length of userA's identification,presentation in ASCII code
	unsigned char *message="message digest";//the message to be signed
	int len=strlen(message);//the length of message
	unsigned char ZA[SM3_len/8];//ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	unsigned char Msg[210]; //210=IDA_len+2+SM2_NUMWORD*6
	int temp;

	miracl *mip=mirsys(10000,16);
	mip->IOBASE=16;
	temp=SM2_KeyGeneration(dA,xA,yA);
	if(temp)
		return temp;

	// ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA
	memcpy(Msg,ENTLA,2);
	memcpy(Msg+2,IDA,IDA_len);
	memcpy(Msg+2+IDA_len,SM2_a,SM2_NUMWORD);
	memcpy(Msg+2+IDA_len+SM2_NUMWORD,SM2_b,SM2_NUMWORD);
	memcpy(Msg+2+IDA_len+SM2_NUMWORD*2,SM2_Gx,SM2_NUMWORD);
	memcpy(Msg+2+IDA_len+SM2_NUMWORD*3,SM2_Gy,SM2_NUMWORD);
	memcpy(Msg+2+IDA_len+SM2_NUMWORD*4,xA,SM2_NUMWORD);
	memcpy(Msg+2+IDA_len+SM2_NUMWORD*5,yA,SM2_NUMWORD);

	SM3_256(Msg,210,ZA);

	temp=SM2_Sign(message,len,ZA,rand,dA,r,s);
	if(temp)
		return temp;

	
	for(i=0;i<1000;i++)
		temp=SM2_Verify(message,len,ZA,xA,yA,r,s);
	if(temp){
		printf(" sm2 sv err \n");
		return temp;
	}else
		printf("sm2 sv ok \n");
	return 0;
}
