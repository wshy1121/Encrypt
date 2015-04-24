#ifndef _VERIFY_HANDLE_H_
#define _VERIFY_HANDLE_H_

#include "data_handle.h"
#include "user_manager.h"

class CVerifyHandle : public IDealDataHandle
{
public:
	CVerifyHandle();
public:
	void login(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf);
	void accessRep(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf);
	void verifyAccess(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf);
	void getClientInf(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf);
private:
	bool isAvailable(TimeCalcInf *pCalcInf);
};

class CVerifyClient
{
public:
	static CVerifyClient *instance();
public:
	bool login(char *userName, char *passWord);
	bool createAccess(char *access, int &accessLen);	
	bool getAccessRep(char *access, int accessLen, char *accessRep);
	bool verifyAccess(char *access, int accessLen, char *accessRep);
	bool getClientInf(CClientInf *clientInf);
private:
	CVerifyClient();
private:
	static CVerifyClient *_instance;

};

#endif

