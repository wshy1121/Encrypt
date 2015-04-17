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
	bool createKeyInf(char *keyInf, int keyInfLen);
	bool encode(char *keyInf, int keyInfLen, char *pSrc, int srcLen, char *pDst, int &dstLen);
	bool decode(char *keyInf, int keyInfLen, char *pSrc, int srcLen, char *pDst);
	bool createAccess(char *access, int &accessLen);
	bool createAccessRep(char *access, int accessLen, char *accessRep);	
	bool verifyAccess(char *access, int accessLen, char *accessRep);
	int encryptMac(unsigned char *src, int vnLen, unsigned char *mac);
	bool isAccAvailable(char *access, int accessLen);
private:
	CSafeServer();
	bool getRealKey(uchar *keyInf, int keyInfLen, uchar *pKey);
	bool getAccessKeyInf(char *keyInf, int keyInfLen);
	int termXorMac(char *pData, int nLen, char *pMac, int * pnMacLen);
	char createAccMac(char *access, int accessLen);
private:	
	static  CSafeServer* _instance;
private:
	uchar m_mainKey[SAFE_KEY_LEN];
	uchar m_keyMap[KEY_MAP_SIZE];
	uchar m_accessMap[KEY_MAP_SIZE];
};
#endif

