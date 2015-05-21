#include "stdafx.h"
#include "verify_handel.h"
#include "safe_server.h"
#include "link_tool.h"
#include "net_client.h"
#include "user_manager.h"

using namespace base;
extern CPthreadMutex g_insMutexCalc;

CVerifyHandle::CVerifyHandle()
{
	addMethod("login", (IDealDataHandle::Method)&CVerifyHandle::login);
	addMethod("accessRep", (IDealDataHandle::Method)&CVerifyHandle::accessRep);
	addMethod("verifyAccess", (IDealDataHandle::Method)&CVerifyHandle::verifyAccess);
	addMethod("getClientInf", (IDealDataHandle::Method)&CVerifyHandle::getClientInf);
}


bool CVerifyHandle::isAvailable(TimeCalcInf *pCalcInf)
{	trace_worker();
	CClientInf *clientInf = pCalcInf->m_clientInf.get();
	bool bRet = CUserManager::instance()->isLogined(clientInf);
	trace_printf("bRet  %d", bRet);
	return bRet;
}

void CVerifyHandle::login(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf)
{
	CLogDataInf &dataInf = pCalcInf->m_dataInf;

	char *oper = dataInf.m_infs[0];
	char *sessionId = dataInf.m_infs[1];
	
	char *keyInf = dataInf.m_infs[2];
	int keyInfLen = dataInf.m_infLens[2];
	
	char *userName = dataInf.m_infs[3];	
	int userNameLen = dataInf.m_infLens[3];
	
	char *passWord = dataInf.m_infs[4];
	int passWordLen = dataInf.m_infLens[4];


	CSafeServer::instance()->decode(keyInf, keyInfLen, userName, userNameLen,userName);
	CSafeServer::instance()->decode(keyInf, keyInfLen, passWord, passWordLen,passWord);
	printf("CVerify::dealDataHandle %s  %s  %s\n", oper, userName, passWord);
	CClientInf *clientInf = pCalcInf->m_clientInf.get();
	CUserManager::instance()->login(userName, passWord, clientInf);
	
	{
		CLogDataInf &dataInf = repCalcInf->m_dataInf;
		
		char keyInf[KEY_INF_LEN];
		CSafeServer::instance()->createKeyInf(keyInf, sizeof(keyInf));

		char _userName[32];
		int _userNameLen = sizeof(_userName);
		CSafeServer::instance()->encode(keyInf, sizeof(keyInf), userName, strlen(userName)+1, _userName, _userNameLen);

		char _passWord[32];
		int _passWordLen = sizeof(_passWord);
		CSafeServer::instance()->encode(keyInf, sizeof(keyInf), passWord, strlen(passWord)+1, _passWord, _passWordLen);

		dataInf.putInf(oper);
		dataInf.putInf(sessionId);//session id(大于0)
		dataInf.putInf(keyInf, sizeof(keyInf));//密钥
		dataInf.putInf(_userName, _userNameLen);//用户名
		dataInf.putInf(_passWord, _passWordLen); //密码
		dataInf.packet();

	}
}

void CVerifyHandle::accessRep(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf)
{	trace_worker();

	if (!isAvailable(pCalcInf))
	{	trace_printf("NULL");
		return ;
	}
	CLogDataInf &dataInf = pCalcInf->m_dataInf;
	char *oper = dataInf.m_infs[0];
	char *sessionId = dataInf.m_infs[1];

	char *access = dataInf.m_infs[2];	
	int accessLen = dataInf.m_infLens[2];
	char accessRep[32];

	bool bRet = CSafeServer::instance()->isAccAvailable(access, accessLen);
	if (!bRet)
	{	trace_printf("NULL");
		return ;
	}
	bRet = CSafeServer::instance()->createAccessRep(access, accessLen, accessRep);
	if (!bRet)
	{	trace_printf("NULL");
		return ;
	}
	{	trace_printf("NULL");
		CLogDataInf &dataInf = repCalcInf->m_dataInf;
		dataInf.putInf(oper);
		dataInf.putInf(sessionId);//session id(大于0)
		dataInf.putInf(accessRep, accessLen);//accessRep
		dataInf.packet();
	}
	trace_printf("NULL");	
}

void CVerifyHandle::verifyAccess(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf)
{	trace_worker();
	TraceInfoId &traceInfoId = pCalcInf->m_traceInfoId;


	CLogDataInf &dataInf = pCalcInf->m_dataInf;
	char *oper = dataInf.m_infs[0];
	char *sessionId = dataInf.m_infs[1];

	char *access = dataInf.m_infs[2];	
	int accessLen = dataInf.m_infLens[2];
	char *accessRep = dataInf.m_infs[3];

	bool bRet = CUserManager::instance()->verifyAccess(access, accessLen, accessRep);
	trace_printf("bRet  %d", bRet);
	if (!bRet)
	{	trace_printf("NULL");
		return ;
	}
	trace_printf("NULL");
	{
		CLogDataInf &dataInf = repCalcInf->m_dataInf;
		dataInf.putInf(oper);
		dataInf.putInf(sessionId);//session id(大于0)
		dataInf.packet();
	}	
	return ;
}

void CVerifyHandle::getClientInf(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf)
{
	CLogDataInf &reqDataInf = pCalcInf->m_dataInf;
	char *oper = reqDataInf.m_infs[0];
	char *sessionId = reqDataInf.m_infs[1];
	
	CClientInf *clientInf = pCalcInf->m_clientInf.get();
	CLogDataInf &repDataInf = repCalcInf->m_dataInf;
	repDataInf.putInf(oper);
	repDataInf.putInf(sessionId);//session id(大于0)
	repDataInf.putInf((char *)clientInf->m_userName.c_str());
	repDataInf.putInf((char *)clientInf->m_passWord.c_str());
	repDataInf.putInf((char *)clientInf->m_logPath.c_str());
	repDataInf.putInf((char *)clientInf->m_fileName.c_str());
	repDataInf.packet();

}

CVerifyClient *CVerifyClient::_instance;

CVerifyClient *CVerifyClient::instance()
{
	if (NULL == _instance)
	{
		CGuardMutex guardMutex(g_insMutexCalc);
		if (NULL == _instance)
		{
			_instance = new CVerifyClient;
		}
	}
	return _instance;
}
CVerifyClient::CVerifyClient()
{
}


bool CVerifyClient::login(char *userName, char *passWord)
{
	char sessionId[16];
	snprintf(sessionId, sizeof(sessionId), "%d", CNetClient::instance()->getSessionId());
	
	char keyInf[KEY_INF_LEN];
	CSafeServer::instance()->createKeyInf(keyInf, sizeof(keyInf));

	char _userName[32];
	int _userNameLen = sizeof(_userName);
	CSafeServer::instance()->encode(keyInf, sizeof(keyInf), userName, strlen(userName)+1, _userName, _userNameLen);

	char _passWord[32];
	int _passWordLen = sizeof(_passWord);
	CSafeServer::instance()->encode(keyInf, sizeof(keyInf), passWord, strlen(passWord)+1, _passWord, _passWordLen);

	CLogDataInf dataInf;
	dataInf.putInf((char *)"login");
	dataInf.putInf(sessionId);//session id(大于0)
	dataInf.putInf(keyInf, sizeof(keyInf));//密钥
	dataInf.putInf(_userName, _userNameLen);//用户名
	dataInf.putInf(_passWord, _passWordLen); //密码

	char *packet = NULL;
	int packetLen = dataInf.packet(packet);
	CNetClient::instance()->dealPacket(packet, packetLen, dataInf);
	

	{
		char *oper = dataInf.m_infs[0];
		char *sessionId = dataInf.m_infs[1];
		
		char *keyInf = dataInf.m_infs[2];
		int keyInfLen = dataInf.m_infLens[2];
		
		char *decUserName = dataInf.m_infs[3]; 
		int userNameLen = dataInf.m_infLens[3];
		
		char *decPassWord = dataInf.m_infs[4];
		int passWordLen = dataInf.m_infLens[4];
		
		
		CSafeServer::instance()->decode(keyInf, keyInfLen, decUserName, userNameLen,decUserName);
		CSafeServer::instance()->decode(keyInf, keyInfLen, decPassWord, passWordLen,decPassWord);
		printf("CNetClient::verify %s	%s	%s\n", oper, decUserName, decPassWord);

		if (!strcmp(userName, decUserName) && !strcmp(passWord, decPassWord))
		{
			return true;
		}
		else
		{
			return false;
		}

	}
	return true;
}



bool CVerifyClient::createAccess(char *access, int &accessLen)
{
	return CSafeServer::instance()->createAccess(access, accessLen);
}

bool CVerifyClient::getAccessRep(char *access, int accessLen, char *accessRep)
{
	char sessionId[16];
	snprintf(sessionId, sizeof(sessionId), "%d", CNetClient::instance()->getSessionId());

	CLogDataInf dataInf;
	dataInf.putInf((char *)"accessRep");
	dataInf.putInf(sessionId);//session id(大于0)
	dataInf.putInf(access, accessLen);//access

	char *packet = NULL;
	int packetLen = dataInf.packet(packet);
	CNetClient::instance()->dealPacket(packet, packetLen, dataInf);
	
	memcpy(accessRep, dataInf.m_infs[2], accessLen);
	accessRep[accessLen] = '\0';
	return true;
}

bool CVerifyClient::verifyAccess(char *access, int accessLen, char *accessRep)
{	trace_worker();
	bool bRet = CSafeServer::instance()->verifyAccess(access, accessLen, accessRep);
	if (!bRet)
	{	trace_printf("NULL");
		return false;
	}
	trace_printf("NULL");	
	char sessionId[16];
	snprintf(sessionId, sizeof(sessionId), "%d", CNetClient::instance()->getSessionId());

	CLogDataInf dataInf;
	dataInf.putInf((char *)"verifyAccess");
	dataInf.putInf(sessionId);//session id(大于0)
	dataInf.putInf(access, accessLen);//access
	dataInf.putInf(accessRep, accessLen);//accessRep
	
	trace_printf("NULL");
	char *packet = NULL;
	int packetLen = dataInf.packet(packet);
	CNetClient::instance()->dealPacket(packet, packetLen, dataInf);
	
	trace_printf("NULL");

	if (dataInf.m_infsNum == 0)
	{	trace_printf("NULL");
		return false;
	}
	return true;
}


bool CVerifyClient::getClientInf(CClientInf *clientInf)
{	trace_worker();
	char sessionId[16];
	snprintf(sessionId, sizeof(sessionId), "%d", CNetClient::instance()->getSessionId());

	CLogDataInf dataInf;
	dataInf.putInf((char *)"getClientInf");
	dataInf.putInf(sessionId);//session id(大于0)

	char *packet = NULL;
	int packetLen = dataInf.packet(packet);
	CNetClient::instance()->dealPacket(packet, packetLen, dataInf);
	

	if (dataInf.m_infsNum == 0)
	{	trace_printf("NULL");
		return false;
	}
	trace_printf("NULL");

	clientInf->m_userName = dataInf.m_infs[2];
	clientInf->m_passWord = dataInf.m_infs[3];
	clientInf->m_logPath = dataInf.m_infs[4];	
	clientInf->m_fileName = dataInf.m_infs[5];	
	return true;
}

