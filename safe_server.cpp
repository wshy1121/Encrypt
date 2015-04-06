#include "stdafx.h"
#include <stdlib.h>
#include <time.h>
#include "string_base.h"
#include "des.h"
#include "link_tool.h"
#include "safe_server.h"
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
}


//主密钥索引(16字节)+密钥索引映射表(256字节)+实际密钥索引(16字节)
bool CSafeServer::encode(uchar *keyInf, int keyInfLen, char *pSrc, int srcLen, char *pDst)
{
	bool bRet = true;
	uchar realKey[SAFE_KEY_LEN];
	bRet = getRealKey(keyInf, keyInfLen, realKey);
	if (!bRet)
	{
		return false;
	}
	
	return true;
}

bool CSafeServer::createKeyInf(uchar *keyInf, int keyInfLen)
{
	if (keyInfLen != KEY_INF_LEN)
	{
		return false;
	}
	for (int i=0; i<keyInfLen; ++i)
	{
		keyInf[i] = rand() % 256;
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
	uchar realKey[keyLen];
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


