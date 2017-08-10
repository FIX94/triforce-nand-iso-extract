/*
 * Copyright (C) 2017 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <malloc.h>
#include "des.h"

/* Triforce games are encrypted a little weird */
static inline void do64BitSwap(void *in, void *out)
{
	*(unsigned long long*)out = __builtin_bswap64(*(unsigned long long*)in);
}

static struct _des_ctx DESctx;
/* Just a helper function for me to not get confused */
static inline void des_ecb_decrypt_swapped(struct _des_ctx *ctx, void *in, void *out) 
{
	do64BitSwap(in,out); //out is now the swapped input
	des_ecb_decrypt(ctx,out,out); //out is now swapped decrypted
	do64BitSwap(out,out); //out is now decrypted
}

static inline void interleave(uint8_t *in1, uint8_t *in2, uint32_t inlen, uint8_t *out)
{
	uint32_t i;
	for(i = 0; i < inlen; i++)
	{
		out[(i<<1)|0]=in1[i];
		out[(i<<1)|1]=in2[i];
	}
}

static inline void des_decrypt_block(uint8_t *buf)
{
	uint32_t i;
	for(i = 0; i < 0x400; i+=8)
		des_ecb_decrypt_swapped(&DESctx, buf+i, buf+i);
}

static void combine_dec(char *in1, char *in2, uint32_t inlen, FILE *out)
{
	FILE *f1 = fopen(in1,"rb");
	FILE *f2 = fopen(in2,"rb");
	uint32_t i;
	uint8_t buf1[0x200], buf2[0x200], outbuf[0x400];
	for(i = 0; i < inlen; i+=0x200)
	{
		fread(buf1,1,0x200,f1);
		fread(buf2,1,0x200,f2);
		interleave(buf1,buf2,0x200,outbuf);
		des_decrypt_block(outbuf);
		fwrite(outbuf,1,0x400,out);
		//skip over verification? block
		fseek(f1,0x10,SEEK_CUR);
		fseek(f2,0x10,SEEK_CUR);
		i+=0x10;
	}
	fclose(f1);
	fclose(f2);
}

static void addMissing(FILE *out)
{
	//16mb should be enough
	uint8_t *buf = malloc(0x1000000);
	//start copy operation
	FILE *in = fopen("MARIOKARTGP2.BIN","rb");
	//handle gap from 0x07800000 to 0x08000000
	fseek(in,0x07440000,SEEK_SET);
	fread(buf,1,0x930000,in);
	fseek(out,0x07590000,SEEK_SET);
	fwrite(buf,1,0x930000,out);
	//correct boot.id region
	fseek(out,0x7D50B80+0x38,SEEK_SET);
	buf[0] = 0x02; //JAPAN
	fwrite(buf,1,1,out);
	//CAM DSPs will be missing :(
	fseek(out,0x7EC0000,SEEK_SET);
	memset(buf,0,0x3F1C4);
	fwrite(buf,1,0x3F1C4,out);
	//same files from this point
	fseek(in,0x07D9F1C4,SEEK_SET);
	fread(buf,1,0x10589C,in);
	fseek(out,0x07EFF1C4,SEEK_SET);
	fwrite(buf,1,0x10589C,out);
	//handle gap from 0x0F800000 to 0x10000000
	fseek(in,0x0F7FFEC0,SEEK_SET);
	fread(buf,1,0xBA1740,in);
	fseek(out,0x0F7FFEC0,SEEK_SET);
	fwrite(buf,1,0xBA1740,out);
	//handle gap from 0x17800000 to 0x18000000
	fseek(in,0x177E1D20,SEEK_SET);
	fread(buf,1,0x82EFE0,in);
	fseek(out,0x177E1D20,SEEK_SET);
	fwrite(buf,1,0x82EFE0,out);
	//done
	fclose(in);
	free(buf);
}

static bool verifyFiles()
{
	FILE *f = fopen("MARIOKARTGP2.BIN","rb");
	if(!f)
	{
		printf("MARIOKARTGP2.BIN missing!\n");
		return false;
	}
	fseek(f,0,SEEK_END);
	if(ftell(f) != 0x1E000000)
	{
		printf("MARIOKARTGP2.BIN has the wrong length!\n");
		fclose(f);
		return false;
	}
	fclose(f);
	int i;
	char name[32];
	for(i = 1; i <= 8; i++)
	{
		sprintf(name,"ic%i_k9f1208u0b.bin",i);
		f = fopen(name,"rb");
		if(!f)
		{
			printf("%s missing!\n", name);
			return false;
		}
		fseek(f,0,SEEK_END);
		if(ftell(f) != 0x4200000)
		{
			printf("%s has the wrong length!\n", name);
			fclose(f);
			return false;
		}
		fclose(f);
	}
	return true;
}

static const unsigned long long gp2key[1] = { 0xCFA3131991992F2B };

static const unsigned char gp2jHdr[0x40] = { /* GGPJ02 - Mario Kart Arcade GP 2 */
	0x47, 0x47, 0x50, 0x4A, 0x30, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x33, 0x9F, 0x3D, 0x4D, 0x61, 0x72, 0x69, 0x6F, 0x20, 0x4B, 0x61, 0x72, 0x74, 0x20, 0x41, 
	0x72, 0x63, 0x61, 0x64, 0x65, 0x20, 0x47, 0x50, 0x20, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int main()
{
	printf("Triforce NAND ISO Extract v1.0 by FIX94\n");
	printf("Checking files...\n");
	if(!verifyFiles())
		return 0;
	FILE *out = fopen("OUT.BIN","wb+");
	if(!out)
	{
		printf("OUT.BIN not writable!\n");
		return 0;
	}
	des_setkey(&DESctx, (unsigned char*)(gp2key));
	printf("Combining and decrypting");
	combine_dec("ic1_k9f1208u0b.bin","ic2_k9f1208u0b.bin",0x4200000,out);
	printf(".");
	combine_dec("ic3_k9f1208u0b.bin","ic4_k9f1208u0b.bin",0x4200000,out);
	printf(".");
	combine_dec("ic5_k9f1208u0b.bin","ic6_k9f1208u0b.bin",0x4200000,out);
	printf(".");
	combine_dec("ic7_k9f1208u0b.bin","ic8_k9f1208u0b.bin",0x317FFF0,out);
	printf(".\nFixing and adding US Data\n");
	addMissing(out);
	printf("Adding Header\n");
	fseek(out,0,SEEK_SET);
	fwrite(gp2jHdr,1,0x40,out);
	fclose(out);
	printf("Done!\n");
	return 0;
}