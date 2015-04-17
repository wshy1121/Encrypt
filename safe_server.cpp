#include "stdafx.h"
#include <stdlib.h>
#include <time.h>
#include "string_base.h"
#include "des.h"
#include "link_tool.h"
#include "safe_server.h"
#include "defs.h"
using namespace base;

extern CPthreadMutex g_insMutexCalc;
CSafeServer* CSafeServer::_instance = NULL;

CSafeServer* CSafeServer::instance() 
{	
	if (NULL == _instance)
	{
		CGuardMutex guardMutex(g_insMutexCalc);
		if (NULL == _instance)
		{
			_instance = new CSafeServer;
		}
	}
	return _instance;
}


CSafeServer::CSafeServer()
{
	srand((int)time(0));
	
	base::strcpy((char *)m_mainKey, "amwfqp1121amwfqp");
	memset(m_keyMap, 0, sizeof(m_keyMap));
	
	int keyLen = SAFE_KEY_LEN / 2;	
	uchar *key = NULL;
	for (int i=0; i<KEY_MAP_SIZE;)
	{
		key = m_keyMap + i;
		memset(key, i, keyLen);
		Encode(TR_DES, key, keyLen, key, &keyLen, m_mainKey);
		i+= keyLen;
	}

	char keyArray[] = "qwertyuiopasdfghjklzxcvbnm";
	for (int i=0; i<KEY_MAP_SIZE; ++i)
	{
		m_accessMap[i] = keyArray[m_keyMap[i] % 26];
	}
}


//主密钥索引(16字节)+密钥索引映射表(256字节)+实际密钥索引(16字节)
bool CSafeServer::encode(char *keyInf, int keyInfLen, char *pSrc, int srcLen, char *pDst, int &dstLen)
{
	int tmpDstLen = (srcLen + 7) / 8 * 8;
	if (dstLen < tmpDstLen || keyInfLen != KEY_INF_LEN)
	{
		return false;
	}
	dstLen = tmpDstLen;
	
	bool bRet = true;
	uchar realKey[SAFE_KEY_LEN];
	bRet = getRealKey((uchar *)keyInf, keyInfLen, realKey);
	if (!bRet)
	{
		return false;
	}

	Encode(TR_DES, (uchar *)pSrc, srcLen, (uchar *)pDst, &dstLen, realKey);
	return true;
}

bool CSafeServer::decode(char *keyInf, int keyInfLen, char *pSrc, int srcLen, char *pDst)
{
	if (keyInfLen != KEY_INF_LEN)
	{
		return false;
	}

	bool bRet = true;
	uchar realKey[SAFE_KEY_LEN];
	bRet = getRealKey((uchar *)keyInf, keyInfLen, realKey);
	if (!bRet)
	{
		return false;
	}

	Decode(TR_DES, (uchar *)pSrc, srcLen, (uchar *)pDst, realKey);
	return true;
}

bool CSafeServer::createKeyInf(char *keyInf, int keyInfLen)
{
	if (keyInfLen != KEY_INF_LEN)
	{
		return false;
	}
	for (int i=0; i<keyInfLen; ++i)
	{
		keyInf[i] = rand() % KEY_MAP_SIZE;
	}
	return true;
}

bool CSafeServer::getAccessKeyInf(char *keyInf, int keyInfLen)
{
	if (keyInfLen != KEY_INF_LEN)
	{
		return false;
	}
	memset(keyInf, '0x11', keyInfLen);
	for (int i=0; i<KEY_MAP_SIZE; ++i)
	{
		keyInf[i] = m_keyMap[i];
	}
	return true;
}

bool CSafeServer::getRealKey(uchar *keyInf, int keyInfLen, uchar *pKey)
{
	const int keyLen = SAFE_KEY_LEN;
	if (keyInfLen != KEY_INF_LEN)
	{
		return false;
	}
	
	uchar realKeyInf[KEY_INF_LEN];
	memset(realKeyInf, 0, sizeof(realKeyInf));
	
	//解密keyInf
	for (int i=0; i<KEY_INF_LEN;)
	{
		Decode(TR_DES, keyInf + i, keyLen, realKeyInf + i, m_mainKey);
		i+= keyLen;
	}

	int pos = 0;
	//获取主密钥
	uchar *mainKeyIndexs = realKeyInf + pos;
	uchar *mainKey = realKeyInf + pos;
	for (int i=0; i<keyLen; ++i)
	{
		mainKey[i] = m_keyMap[mainKeyIndexs[i]];
	}
	pos += keyLen;
	//获取密钥索引映射表:先用主密钥解密，再用m_keyMap 映射回来	
	uchar *keyMapIndexs = realKeyInf + pos;
	uchar *realKeyMap = realKeyInf + pos;
	for (int i=0; i<KEY_MAP_SIZE;)
	{
		Decode(TR_DES, keyMapIndexs, keyLen, keyMapIndexs, mainKey);
		i+= keyLen;
	}
	for (int i=0; i<KEY_MAP_SIZE; ++i)
	{
		realKeyMap[i] = m_keyMap[keyMapIndexs[i]];
	}
	pos += KEY_MAP_SIZE;
	
	//获取实际密钥
	uchar *realKeyIndexs = realKeyInf + pos;
	uchar *realKey = realKeyInf + pos;
	Decode(TR_DES, realKeyIndexs, keyLen, realKeyIndexs, mainKey);
	for (int i=0; i<keyLen; ++i)
	{
		realKeyIndexs[i] = m_keyMap[realKeyIndexs[i]];
	}
	for (int i=0; i<keyLen; ++i)
	{
		realKey[i] = realKeyMap[realKeyIndexs[i]];
	}
	pos += keyLen;

	memcpy(pKey, realKey, keyLen);
	return true;
}

bool CSafeServer::createAccess(char *access, int &accessLen)
{
	if (accessLen < 8)
	{
		return false;
	}
	char &accessMac = access[7];
	accessMac = 0;
	accessLen = 8;
	for (int i=0; i<accessLen-1; ++i)
	{
		access[i] = m_accessMap[(uchar)(rand() % KEY_MAP_SIZE)];
		accessMac ^= access[i];
	}
	accessMac = m_accessMap[accessMac];	 
	access[accessLen] = '\0';
	return true;
}

bool CSafeServer::createAccessRep(char *access, int accessLen, char *accessRep)
{	trace_worker();
	char keyInf[KEY_INF_LEN];
	getAccessKeyInf(keyInf, sizeof(keyInf));
	CSafeServer::instance()->decode(keyInf, sizeof(keyInf), access, accessLen, accessRep);

	for (int i=0; i<accessLen; ++i)
	{
		accessRep[i] = m_accessMap[(uchar)accessRep[i]];
	}
	accessRep[accessLen] = '\0';
	return true;
}

char CSafeServer::createAccMac(char *access, int accessLen)
{	trace_worker();
	char accessMac = 0;
	for (int i=0; i<accessLen-1; ++i)
	{
		accessMac ^= access[i];
	}
	accessMac = m_accessMap[accessMac];
	return accessMac;
}

bool CSafeServer::verifyAccess(char *access, int accessLen, char *accessRep)
{	trace_worker();
	trace_printf("accessLen  %d", accessLen);

	char accessMac = createAccMac(access, accessLen);
	if (accessMac != access[accessLen-1])
	{	trace_printf("NULL");
		return false;
	}
	
	char tmpAccessRep[32];
	bool bRet = createAccessRep(access, accessLen, tmpAccessRep);
	if (!bRet)
	{	trace_printf("NULL");
		return false;
	}

	if (memcmp(tmpAccessRep, accessRep, accessLen))
	{	trace_printf("NULL");
		return false;
	}
	trace_printf("NULL");	
	return true;
}

int CSafeServer::termXorMac(char *pData, int nLen, char *pMac, int * pnMacLen)
{
	char mac_block[8];
	char tmp[16];
	int i, k;

	memset(mac_block, 0, 8);
	k = (nLen) / 8;
	for (i = 0; i < k; ++ i)
		Xor(mac_block, pData + i * 8, 8);

	Xor(mac_block, pData + k * 8, nLen % 8);


	DES3(mac_block, tmp, (char *)m_mainKey, ENCODE);

	memcpy(pMac, tmp, 8);
	*pnMacLen = 8;
	return 0;
}

//XOR MAC算法
int CSafeServer::encryptMac(unsigned char *src, int vnLen, unsigned char *mac)
{
	int nRet, i, BlockNum, mac_len;
	unsigned char MacBlock[8];

// 先初始化为8个字节
	memset(MacBlock, 0, 8);
	BlockNum = (vnLen) / 8;
	for (i = 0; i < BlockNum; ++ i)
		Xor((char *)MacBlock, (char *)src + i * 8, 8);
	Xor((char *)MacBlock, (char *)src + BlockNum * 8, vnLen % 8);

//计算MAC
	nRet = termXorMac((char *)MacBlock, 8, (char *)mac, &mac_len);
	if (nRet != 0)
	{
		return -1;
	}
	
	return 0;
}


