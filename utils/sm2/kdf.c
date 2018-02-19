
#include <string.h>
#include "kdf.h"


void SM3_KDF( unsigned char Z[] ,unsigned short zlen,unsigned short klen,unsigned char K[])
{
	unsigned short i,j,t;
	unsigned int bitklen;
	SM3_STATE md;
	unsigned char Ha[SM2_NUMWORD] ;
	unsigned char ct[4]={0,0,0,1};
	bitklen=klen*8;
	if(bitklen%SM2_NUMBITS)
		t=bitklen/SM2_NUMBITS+1;
	else
		t=bitklen/SM2_NUMBITS;
	//s4: K=Ha1||Ha2||...
	for(i=1;i<t;i++)
	{
		//s2: Hai=Hv(Z||ct)
		SM3_init(&md);
		SM3_process(&md, Z, zlen);
		SM3_process(&md, ct, 4);
		SM3_done(&md, Ha);memcpy((K+SM2_NUMWORD*(i-1)), Ha, SM2_NUMWORD);
		if(ct[3]==0xff)
		{
			ct[3]=0;
			if(ct[2]==0xff)
			{
				ct[2]=0;
				if(ct[1]==0xff)
				{
					ct[1]=0;
					ct[0]++;
				}
				else ct[1]++;
			}
			else ct[2]++;
		}
		else ct[3]++;
	}
	//s3: klen/v非整数的处理
	SM3_init(&md);
	SM3_process(&md, Z, zlen);
	SM3_process(&md, ct, 4);
	SM3_done(&md, Ha);
	if(bitklen%SM2_NUMBITS)
	{
		i=(SM2_NUMBITS-bitklen+SM2_NUMBITS*(bitklen/SM2_NUMBITS))/8;
		j=(bitklen-SM2_NUMBITS*(bitklen/SM2_NUMBITS))/8;
		memcpy((K+SM2_NUMWORD*(t-1)), Ha,j);
	}
	else
	{
		memcpy((K+SM2_NUMWORD*(t-1)), Ha,SM2_NUMWORD);
	}
}
