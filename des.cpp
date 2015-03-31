#include "stdafx.h"
#include "des.h"
#include "stdio.h"
#include "string.h"
#include "ctype.h"

//将位扩展成字节
static void ExpandBit(char *p8, char *p64)
{
    int i, j;

    for (i = 0; i < 8; ++ i)
    {
        for (j = 0; j < 8; ++ j)
            p64[i * 8 + j] = (p8[i] >> (7 - j)) & 0x1;        
    }
}

//将字节缩成位
static void ShrinkBit(char *p64, char *p8)
{
    int i, j;

    for (i = 0; i < 8; ++ i)
    {
        for (j = 0; j < 8; ++ j)
        {
            if (p64[i * 8 + j] == 0)
                p8[i] &= (~(0x80 >> j)) & 0xFF;
            else
                p8[i] |= (0x80 >> j) & 0xFF;
        }
    }
}

void Xor(char *pX1, char *pX2, int nLen)
{
    int i;

    for (i = 0; i < nLen; ++ i)
        pX1[i] ^= pX2[i];
}

//初始置换
static void IP(char *p64) 
{
    char mapper[64] = {
        57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
        56, 48, 40, 32, 24, 16,  8,  0, 58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6,
    };
    char tmp[64];
    int i;

    for (i = 0; i < 64; ++ i)
        tmp[i] = p64[mapper[i]];

    memcpy(p64, tmp, 64);
}

//末置换
static void EP(char *p64)
{
    char mapper[64] = {
        39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27, 34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25, 32,  0, 40,  8, 48, 16, 56, 24,
    };
    char tmp[64];
    int i;

    for (i = 0; i < 64; ++ i)
        tmp[i] = p64[mapper[i]];

    memcpy(p64, tmp, 64);
}

//将8字节密钥,扩展并置换成56字节模式
static void InitKey(char *p8, char *p56)
{
    char mapper[] = {
        56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,  
         9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35, 
        62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21, 
        13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3,
    };
    char tmp[64];
    int i;
    
    ExpandBit(p8, tmp);

    for (i = 0; i < 56; ++ i)
        p56[i] = tmp[mapper[i]];    
}

static void LShift(char *p28, int nShift)
{
    char tmp[28];
    int i;

    memcpy(tmp, p28, 28);

    nShift %= 28;
    i = 28 - nShift;

    memcpy(p28, tmp + nShift, i);
    memcpy(p28 + i, tmp, nShift);
}

static void RShift(char *p28, int nShift)
{
    char tmp[28];
    int i;

    memcpy(tmp, p28, 28);

    nShift %= 28;
    i = 28 - nShift;

    memcpy(p28 + nShift, tmp, i);
    memcpy(p28, tmp + i, nShift);
}

//计算子密钥
static void SubKey(char *p56, char *p48, int nRound, char cFlag)
{
    char mapper[] = {
        13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
    };
    char L_shift[] = {
        0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, 
    };
    char R_shift[] = {
        0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
    };
    int i;
	
    if (cFlag == ENCODE)
    {
        LShift(p56, L_shift[nRound]);
        LShift(p56 + 28, L_shift[nRound]);
    }
    else
    {
        RShift(p56, R_shift[nRound]);
        RShift(p56 + 28, R_shift[nRound]);
    }

    for (i = 0; i < 48; ++ i)
        p48[i] = p56[mapper[i]];
}

//扩展置换 32字节 -> 48字节
static void EXP(char *p32, char *p48)
{
    char mapper[] = {
        31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,
         7,  8,  9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0,
    };
    int i;

    for (i = 0; i < 48; ++ i)
        p48[i] = p32[mapper[i]];
}

//S盒置换
static void S(char *p48, char *p32)
{
    char s_box[8][4][16] = {
        {
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
            { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
        },
        {
            {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
            { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
        },
        {
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
        },
        {
            { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
            {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
            { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
        },
        {
            { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
            { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
            {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
        },
        {
            {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
        },
        {
            { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
            { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
            { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
        },
        {
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
            { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
        },
    };
    int i, j, k, row, col;

    for (i = 0, j = 0; i < 48; i += 6, j += 4)
    {
        row = (p48[i] << 1) + p48[i + 5];
        col = (p48[i + 1] << 3) + (p48[i + 2] << 2) + 
              (p48[i + 3] << 1) + p48[i + 4];
        k = s_box[i / 6][row][col];

        p32[j + 0] = (k >> 3) & 0x1;
        p32[j + 1] = (k >> 2) & 0x1;
        p32[j + 2] = (k >> 1) & 0x1;
        p32[j + 3] = k & 0x1;
    }
}

//P盒置换
static void P(char *p32)
{
    char mapper[] = {
        15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
         1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24,
    };
    char tmp[32];
    int i;

    for (i = 0; i < 32; ++ i)
        tmp[i] = p32[mapper[i]];

    memcpy(p32, tmp, 32);
}

void DES(char *pSrc, char *pDst, char *pKey, char flag)
{
    char data[64], tmp[48], key[56], subkey[48];
    int i;

    ExpandBit(pSrc, data);//扩展位到字节
    IP(data);             //初始置换

    InitKey(pKey, key);   //初始56位密钥

    for (i = 1; i <= 16; ++ i) //16轮运算
    {
         SubKey(key, subkey, i, flag); //产生本轮子密钥
        
         EXP(data + 32, tmp); //右32字节扩展为48字节
         
         Xor(tmp, subkey, 48); //与子密钥异或
         
         memcpy(subkey, data + 32, 32); //保存右半部分
         
         S(tmp, data + 32); //S盒代替
         
         P(data + 32); //P盒置换

         Xor(data + 32, data, 32); //与左半部分异或,产生右半

         memcpy(data, subkey, 32); //原右半变为左半
    }

    //交换左右部分
    memcpy(tmp, data, 32);
    memcpy(data, data + 32, 32);
    memcpy(data + 32, tmp, 32);

    EP(data); //末置换

    ShrinkBit(data, pDst);
}

void DES3(char *pSrc, char *pDst, char *pKey, char flag)
{
    if (flag == ENCODE)
    {
        DES(pSrc, pDst, pKey, ENCODE);
        DES(pDst, pDst, pKey + 8, DECODE);
        DES(pDst, pDst, pKey, ENCODE);
    }
    else
    {
        DES(pSrc, pDst, pKey, DECODE);
        DES(pDst, pDst, pKey + 8, ENCODE);
        DES(pDst, pDst, pKey, DECODE);
    }
}

void Encode(int type, unsigned char *pSrc, int nSrcLen, unsigned char *pDst, int *pnDstLen, unsigned char *pKey)
{
	unsigned char src[512];
	int i, nDstLen = (nSrcLen + 7) / 8 * 8, flag = 0;

	*pnDstLen = nDstLen;

	//补齐数据
	for (i = 0; i < nSrcLen; ++ i)
		src[i] = pSrc[i];
	for (; i < nDstLen; ++ i)
	{
		if (flag == 0)
		{
			src[i] = 0x80;
			flag = 1;
		}
		else
			src[i] = 0x0;
	}
	
	for (i = 0; i < nDstLen; i += 8)
    {
        if(type == TR_DES)
		    DES3((char *)(src + i), (char *)(pDst + i), (char *)pKey, ENCODE);	
        else
            DES((char *)(src + i), (char *)(pDst + i), (char *)pKey, ENCODE);	
    }
}

void Decode(int type, unsigned char *pSrc, int nSrcLen, unsigned char *pDst, unsigned char *pKey)
{
	int i;

	for (i = 0; i < nSrcLen; i += 8)
    {
        if(type == TR_DES)
		    DES3((char *)(pSrc + i), (char *)(pDst + i), (char *)pKey, DECODE);
        else
            DES((char *)(pSrc + i), (char *)(pDst + i), (char *)pKey, DECODE);
    }
}
