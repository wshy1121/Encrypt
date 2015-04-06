#ifndef _SAFE_SERVER_H_
#define _SAFE_SERVER_H_

#define KEY_MAP_SIZE  256
#define SAFE_KEY_LEN  16
#define KEY_INF_LEN (SAFE_KEY_LEN + KEY_MAP_SIZE + SAFE_KEY_LEN)
class CSafeServer
{
public:		
	typedef unsigned char uchar;
	static CSafeServer* instance();
	bool createKeyInf(uchar *keyInf, int keyInfLen);
	bool encode(uchar *keyInf, int keyInfLen, char *pSrc, int srcLen, char *pDst);
private:
	CSafeServer();
	bool getRealKey(uchar *keyInf, int keyInfLen, uchar *pKey);
private:	
	static  CSafeServer* _instance;
private:
	uchar m_mainKey[SAFE_KEY_LEN];
	uchar m_keyMap[KEY_MAP_SIZE];
};
#endif

