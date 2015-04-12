#ifndef _VERIFY_HANDLE_H_
#define _VERIFY_HANDLE_H_

#include "data_handle.h"

class CVerifyHandle : public IDealDataHandle
{
public:
	CVerifyHandle();
public:
	void login(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf);
};

class CVerifyClient
{
public:
	static CVerifyClient *instance();
public:
	bool login(char *userName, char *passWord);
	bool createAccess(char *access, int &accessLen);	
	bool getAccessRep(char *access, int accessLen, char *accessRep);
private:
	CVerifyClient();
private:
	static CVerifyClient *_instance;

};

#endif

