#ifndef _DES_H
#define _DES_H

#define TR_DES		3		// 3DES
#define SG_DES		1		// DES

#define ENCODE		0
#define DECODE		1

void DES(char *pSrc, char *pDst, char *pKey, char flag);

void DES3(char *pSrc, char *pDst, char *pKey, char flag);

void Encode(int type, unsigned char *pSrc, int nSrcLen, unsigned char *pDst, int *pnDstLen, unsigned char *pKey);
void Decode(int type, unsigned char *pSrc, int nSrcLen, unsigned char *pDst, unsigned char *pKey);

void Xor(char *pX1, char *pX2, int nLen);

#endif
