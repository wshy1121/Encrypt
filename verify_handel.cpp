#include "stdafx.h"
#include "verify_handel.h"
#include "safe_server.h"
#include "link_tool.h"
#include "net_client.h"

using namespace base;
extern CPthreadMutex g_insMutexCalc;

CVerifyHandle::CVerifyHandle()
{
	addMethod("login", (IDealDataHandle::Method)&CVerifyHandle::login);
}



void CVerifyHandle::login(TimeCalcInf *pCalcInf, TimeCalcInf *repCalcInf)
{
	base::CLogDataInf &dataInf = pCalcInf->m_dataInf;

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

	{
		base::CLogDataInf &dataInf = repCalcInf->m_dataInf;
		
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
	CNetClient::instance()->send(packet, packetLen);
	CNetClient::instance()->receiveInfData(&dataInf);

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
	return true;
}

