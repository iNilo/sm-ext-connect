/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod Sample Extension
 * Copyright (C) 2004-2008 AlliedModders LLC.  All rights reserved.
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 3.0, as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, AlliedModders LLC gives you permission to link the
 * code of this program (as well as its derivative works) to "Half-Life 2," the
 * "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
 * by the Valve Corporation.  You must obey the GNU General Public License in
 * all respects for all other code used.  Additionally, AlliedModders LLC grants
 * this exception to all derivative works.  AlliedModders LLC defines further
 * exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
 * or <http://www.sourcemod.net/license.php>.
 *
 * Version: $Id$
 */

#include "extension.h"
#include "CDetour/detours.h"
#include "steam/steamclientpublic.h"
#include "steam/isteamuser.h"
#include <sm_stringhashmap.h>

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

Connect g_Connect;		/**< Global singleton for extension's main interface */

SMEXT_LINK(&g_Connect);

ConVar g_ConnectVersion("connect_version", SMEXT_CONF_VERSION, FCVAR_REPLICATED|FCVAR_NOTIFY, SMEXT_CONF_DESCRIPTION " Version");

IGameConfig *g_pGameConf = NULL;
IForward *g_pConnectForward = NULL;

class IClient;
class CBaseClient;

class CBaseServer;

typedef enum EAuthProtocol
{
	k_EAuthProtocolWONCertificate = 1,
	k_EAuthProtocolHashedCDKey = 2,
	k_EAuthProtocolSteam = 3,
} EAuthProtocol;

typedef enum EBeginAuthSessionResult
{
	k_EBeginAuthSessionResultOK = 0,				// Ticket is valid for this game and this steamID.
	k_EBeginAuthSessionResultInvalidTicket = 1,		// Ticket is not valid.
	k_EBeginAuthSessionResultDuplicateRequest = 2,	// A ticket has already been submitted for this steamID
	k_EBeginAuthSessionResultInvalidVersion = 3,	// Ticket is from an incompatible interface version
	k_EBeginAuthSessionResultGameMismatch = 4,		// Ticket is not for this game
	k_EBeginAuthSessionResultExpiredTicket = 5,		// Ticket has expired
} EBeginAuthSessionResult;

typedef struct netadr_s
{
private:
	typedef enum
	{
		NA_NULL = 0,
		NA_LOOPBACK,
		NA_BROADCAST,
		NA_IP,
	} netadrtype_t;

public:
	netadrtype_t	type;
	unsigned char	ip[4];
	unsigned short	port;
} netadr_t;

const char *CSteamID::Render() const
{
	static char szSteamID[64];
	V_snprintf(szSteamID, sizeof(szSteamID), "STEAM_0:%u:%u", (m_unAccountID % 2) ? 1 : 0, (int32)m_unAccountID/2);
	return szSteamID;
}

class CSteam3Server
{
public:
	void *m_pSteamGameServer;
	void *m_pSteamGameServerUtils;
	void *m_pSteamGameServerNetworking;
	void *m_pSteamGameServerStats;
	void *m_pSteamHTTP;
} *g_pSteam3Server;

CBaseServer *g_pBaseServer = NULL;

typedef CSteam3Server *(*Steam3ServerFunc)();

#ifndef WIN32
typedef void (*RejectConnectionFunc)(CBaseServer *, const netadr_t &address, int iClientChallenge, const char *pchReason);
#else
typedef void (__fastcall *RejectConnectionFunc)(CBaseServer *, void *, const netadr_t &address, int iClientChallenge, const char *pchReason);
#endif

#ifndef WIN32
typedef void (*SetSteamIDFunc)(CBaseClient *, const CSteamID &steamID);
#else
typedef void (__fastcall *SetSteamIDFunc)(CBaseClient *, void *, const CSteamID &steamID);
#endif

Steam3ServerFunc g_pSteam3ServerFunc = NULL;
RejectConnectionFunc g_pRejectConnectionFunc = NULL;
SetSteamIDFunc g_pSetSteamIDFunc = NULL;

CSteam3Server *Steam3Server()
{
	if(!g_pSteam3ServerFunc)
		return NULL;

	return g_pSteam3ServerFunc();
}

void RejectConnection(const netadr_t &address, int iClientChallenge, const char *pchReason)
{
	if(!g_pRejectConnectionFunc || !g_pBaseServer)
		return;

#ifndef WIN32
	g_pRejectConnectionFunc(g_pBaseServer, address, iClientChallenge, pchReason);
#else
	g_pRejectConnectionFunc(g_pBaseServer, NULL, address, iClientChallenge, pchReason);
#endif
}

void SetSteamID(CBaseClient *pClient, const CSteamID &steamID)
{
	if(!pClient || !g_pSetSteamIDFunc)
		return;

#ifndef WIN32
	g_pSetSteamIDFunc(pClient, steamID);
#else
	g_pSetSteamIDFunc(pClient, NULL, steamID);
#endif
}

class VFuncEmptyClass{};

int g_nBeginAuthSessionOffset = 0;
int g_nEndAuthSessionOffset = 0;

EBeginAuthSessionResult BeginAuthSession(const void *pAuthTicket, int cbAuthTicket, CSteamID steamID)
{
	if(!g_pSteam3Server || !g_pSteam3Server->m_pSteamGameServer || g_nBeginAuthSessionOffset == 0)
		return k_EBeginAuthSessionResultOK;

	void **this_ptr = *(void ***)&g_pSteam3Server->m_pSteamGameServer;
	void **vtable = *(void ***)g_pSteam3Server->m_pSteamGameServer;
	void *func = vtable[g_nBeginAuthSessionOffset];

	union {
		EBeginAuthSessionResult (VFuncEmptyClass::*mfpnew)(const void *, int, CSteamID);

#ifndef WIN32
		struct {
			void *addr;
			intptr_t adjustor;
		} s;
	} u;

	u.s.addr = func;
	u.s.adjustor = 0;
#else
		void *addr;
	} u;

	u.addr = func;
#endif

	return (EBeginAuthSessionResult)(reinterpret_cast<VFuncEmptyClass*>(this_ptr)->*u.mfpnew)(pAuthTicket, cbAuthTicket, steamID);
}

void EndAuthSession(CSteamID steamID)
{
	if(!g_pSteam3Server || !g_pSteam3Server->m_pSteamGameServer || g_nEndAuthSessionOffset == 0)
		return;

	void **this_ptr = *(void ***)&g_pSteam3Server->m_pSteamGameServer;
	void **vtable = *(void ***)g_pSteam3Server->m_pSteamGameServer;
	void *func = vtable[g_nEndAuthSessionOffset];

	union {
		void (VFuncEmptyClass::*mfpnew)(CSteamID);

#ifndef WIN32
		struct {
			void *addr;
			intptr_t adjustor;
		} s;
	} u;

	u.s.addr = func;
	u.s.adjustor = 0;
#else
		void *addr;
	} u;

	u.addr = func;
#endif

	return (void)(reinterpret_cast<VFuncEmptyClass*>(this_ptr)->*u.mfpnew)(steamID);
}

CDetour *g_Detour_CBaseServer__ConnectClient = NULL;
CDetour *g_Detour_CBaseServer__RejectConnection = NULL;
CDetour *g_Detour_CBaseServer__CheckChallengeType = NULL;
CDetour *g_Detour_CSteam3Server__OnValidateAuthTicketResponse = NULL;

class ConnectClientStorage
{
public:
	void* pThis;

	netadr_t address;
	int nProtocol;
	int iChallenge;
	int iClientChallenge;
	int nAuthProtocol;
	char pchName[255];
	char pchPassword[255];
	char pCookie[255];
	int cbCookie;

	uint64 ullSteamID;
	bool Validated;

	ConnectClientStorage() { }
	ConnectClientStorage(netadr_t address, int nProtocol, int iChallenge, int iClientChallenge, int nAuthProtocol, const char *pchName, const char *pchPassword, const char *pCookie, int cbCookie)
	{
		this->address = address;
		this->nProtocol = nProtocol;
		this->iChallenge = iChallenge;
		this->iClientChallenge = iClientChallenge;
		this->nAuthProtocol = nAuthProtocol;
		strncpy(this->pchName, pchName, sizeof(this->pchName));
		strncpy(this->pchPassword, pchPassword, sizeof(this->pchPassword));
		strncpy(this->pCookie, pCookie, sizeof(this->pCookie));
		this->cbCookie = cbCookie;
		this->Validated = false;
	}
};
StringHashMap<ConnectClientStorage> g_ConnectClientStorage;

bool g_bEndAuthSessionOnRejectConnection = false;
CSteamID g_lastClientSteamID;
bool g_bSuppressCheckChallengeType = false;

DETOUR_DECL_MEMBER9(CBaseServer__ConnectClient, IClient *, netadr_t &, address, int, nProtocol, int, iChallenge, int, iClientChallenge, int, nAuthProtocol, const char *, pchName, const char *, pchPassword, const char *, pCookie, int, cbCookie)
{
	if(nAuthProtocol != k_EAuthProtocolSteam)
	{
		// This is likely a SourceTV client, we don't want to interfere here.
		return DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
	}

	g_pBaseServer = (CBaseServer *)this;

	if(pCookie == NULL || (size_t)cbCookie < sizeof(uint64))
	{
		RejectConnection(address, iClientChallenge, "#GameUI_ServerRejectInvalidSteamCertLen");
		return NULL;
	}

	char ipString[32];
	V_snprintf(ipString, sizeof(ipString), "%u.%u.%u.%u", address.ip[0], address.ip[1], address.ip[2], address.ip[3]);

	char passwordBuffer[255];
	V_strncpy(passwordBuffer, pchPassword, sizeof(passwordBuffer));
	uint64 ullSteamID = *(uint64 *)pCookie;

	void *pvTicket = (void *)((intptr_t)pCookie + sizeof(uint64));
	int cbTicket = cbCookie - sizeof(uint64);

	g_bEndAuthSessionOnRejectConnection = true;
	g_lastClientSteamID = CSteamID(ullSteamID);

	char aSteamID[32];
	V_strncpy(aSteamID, g_lastClientSteamID.Render(), sizeof(aSteamID));

	// If client is in async state remove the old object and fake an async retVal
	// This can happen if the async ClientPreConnectEx takes too long to be called
	// and the client auto-retries.
	bool AsyncWaiting = false;
	ConnectClientStorage Storage;
	if(g_ConnectClientStorage.retrieve(aSteamID, &Storage))
	{
		g_ConnectClientStorage.remove(aSteamID);
		EndAuthSession(g_lastClientSteamID);

		// Only wait for async on auto-retry, manual retries should go through the full chain
		// Don't want to leave the client waiting forever if something breaks in the async forward
		if(Storage.iClientChallenge == iClientChallenge)
			AsyncWaiting = true;
	}

	EBeginAuthSessionResult result = BeginAuthSession(pvTicket, cbTicket, g_lastClientSteamID);
	if(result != k_EBeginAuthSessionResultOK)
	{
		RejectConnection(address, iClientChallenge, "#GameUI_ServerRejectSteam");
		return NULL;
	}

	char rejectReason[255];
	cell_t retVal = 1;

	if(AsyncWaiting)
		retVal = -1; // Fake async return code when waiting for async call
	else
	{
		g_pConnectForward->PushString(pchName);
		g_pConnectForward->PushStringEx(passwordBuffer, sizeof(passwordBuffer), SM_PARAM_STRING_UTF8 | SM_PARAM_STRING_COPY, SM_PARAM_COPYBACK);
		g_pConnectForward->PushString(ipString);
		g_pConnectForward->PushString(aSteamID);
		g_pConnectForward->PushStringEx(rejectReason, sizeof(rejectReason), SM_PARAM_STRING_UTF8 | SM_PARAM_STRING_COPY, SM_PARAM_COPYBACK);
		g_pConnectForward->Execute(&retVal);
		pchPassword = passwordBuffer;
	}

	// k_OnClientPreConnectEx_Reject
	if(retVal == 0)
	{
		RejectConnection(address, iClientChallenge, rejectReason);
		return NULL;
	}

	// k_OnClientPreConnectEx_Async
	if(retVal == -1)
	{
		ConnectClientStorage Storage(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
		Storage.pThis = this;
		Storage.ullSteamID = ullSteamID;

		if(!g_ConnectClientStorage.replace(aSteamID, Storage))
		{
			RejectConnection(address, iClientChallenge, "Internal error.");
			return NULL;
		}

		return NULL;
	}

	// k_OnClientPreConnectEx_Accept
	g_bSuppressCheckChallengeType = true;
	return DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
}

DETOUR_DECL_MEMBER3(CBaseServer__RejectConnection, void, netadr_t &, address, int, iClientChallenge, const char *, pchReason)
{
	if(g_bEndAuthSessionOnRejectConnection)
	{
		EndAuthSession(g_lastClientSteamID);
		g_bEndAuthSessionOnRejectConnection = false;
	}

	return DETOUR_MEMBER_CALL(CBaseServer__RejectConnection)(address, iClientChallenge, pchReason);
}

DETOUR_DECL_MEMBER7(CBaseServer__CheckChallengeType, bool, CBaseClient *, pClient, int, nUserID, netadr_t &, address, int, nAuthProtocol, const char *, pCookie, int, cbCookie, int, iClientChallenge)
{
	if(g_bSuppressCheckChallengeType)
	{
		g_bEndAuthSessionOnRejectConnection = false;

		SetSteamID(pClient, g_lastClientSteamID);

		g_bSuppressCheckChallengeType = false;
		return true;
	}

	return DETOUR_MEMBER_CALL(CBaseServer__CheckChallengeType)(pClient, nUserID, address, nAuthProtocol, pCookie, cbCookie, iClientChallenge);
}

DETOUR_DECL_MEMBER1(CSteam3Server__OnValidateAuthTicketResponse, int, CSteamID *, steamID)
{
	char aSteamID[32];
	V_strncpy(aSteamID, steamID->Render(), sizeof(aSteamID));

	ConnectClientStorage Storage;
	if(g_ConnectClientStorage.retrieve(aSteamID, &Storage))
	{
		Storage.Validated = true;
		g_ConnectClientStorage.replace(aSteamID, Storage);
	}

	return DETOUR_MEMBER_CALL(CSteam3Server__OnValidateAuthTicketResponse)(steamID);
}

bool Connect::SDK_OnLoad(char *error, size_t maxlen, bool late)
{
	char conf_error[255] = "";
	if(!gameconfs->LoadGameConfigFile("connect2.games", &g_pGameConf, conf_error, sizeof(conf_error)))
	{
		if(conf_error[0])
		{
			snprintf(error, maxlen, "Could not read connect2.games.txt: %s\n", conf_error);
		}
		return false;
	}

	if(!g_pGameConf->GetMemSig("CBaseServer__RejectConnection", (void **)(&g_pRejectConnectionFunc)) || !g_pRejectConnectionFunc)
	{
		snprintf(error, maxlen, "Failed to find CBaseServer__RejectConnection function.\n");
		return false;
	}

	if(!g_pGameConf->GetMemSig("CBaseClient__SetSteamID", (void **)(&g_pSetSteamIDFunc)) || !g_pSetSteamIDFunc)
	{
		snprintf(error, maxlen, "Failed to find CBaseClient__SetSteamID function.\n");
		return false;
	}

#ifndef WIN32
	if(!g_pGameConf->GetMemSig("Steam3Server", (void **)(&g_pSteam3ServerFunc)) || !g_pSteam3ServerFunc)
	{
		snprintf(error, maxlen, "Failed to find Steam3Server function.\n");
		return false;
	}
#else
	void *address;
	if(!g_pGameConf->GetMemSig("CBaseServer__CheckMasterServerRequestRestart", &address) || !address)
	{
		snprintf(error, maxlen, "Failed to find CBaseServer__CheckMasterServerRequestRestart function.\n");
		return false;
	}

	//META_CONPRINTF("CheckMasterServerRequestRestart: %p\n", address);
	address = (void *)((intptr_t)address + 1); // Skip CALL opcode
	intptr_t offset = (intptr_t)(*(void **)address); // Get offset

	g_pSteam3ServerFunc = (Steam3ServerFunc)((intptr_t)address + offset + sizeof(intptr_t));
	//META_CONPRINTF("Steam3Server: %p\n", g_pSteam3ServerFunc);
#endif

	g_pSteam3Server = Steam3Server();
	if(!g_pSteam3Server)
	{
		snprintf(error, maxlen, "Unable to get Steam3Server singleton.\n");
		return false;
	}

	/*
	META_CONPRINTF("ISteamGameServer: %p\n", g_pSteam3Server->m_pSteamGameServer);
	META_CONPRINTF("ISteamUtils: %p\n", g_pSteam3Server->m_pSteamGameServerUtils);
	META_CONPRINTF("ISteamMasterServerUpdater: %p\n", g_pSteam3Server->m_pSteamMasterServerUpdater);
	META_CONPRINTF("ISteamNetworking: %p\n", g_pSteam3Server->m_pSteamGameServerNetworking);
	META_CONPRINTF("ISteamGameServerStats: %p\n", g_pSteam3Server->m_pSteamGameServerStats);
	*/

	if(!g_pGameConf->GetOffset("ISteamGameServer__BeginAuthSession", &g_nBeginAuthSessionOffset) || g_nBeginAuthSessionOffset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__BeginAuthSession offset.\n");
		return false;
	}

	if(!g_pGameConf->GetOffset("ISteamGameServer__EndAuthSession", &g_nEndAuthSessionOffset) || g_nEndAuthSessionOffset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__EndAuthSession offset.\n");
		return false;
	}

	CDetourManager::Init(g_pSM->GetScriptingEngine(), g_pGameConf);

	g_Detour_CBaseServer__ConnectClient = DETOUR_CREATE_MEMBER(CBaseServer__ConnectClient, "CBaseServer__ConnectClient");
	if(!g_Detour_CBaseServer__ConnectClient)
	{
		snprintf(error, maxlen, "Failed to detour CBaseServer__ConnectClient.\n");
		return false;
	}
	g_Detour_CBaseServer__ConnectClient->EnableDetour();

	g_Detour_CBaseServer__RejectConnection = DETOUR_CREATE_MEMBER(CBaseServer__RejectConnection, "CBaseServer__RejectConnection");
	if(!g_Detour_CBaseServer__RejectConnection)
	{
		snprintf(error, maxlen, "Failed to detour CBaseServer__RejectConnection.\n");
		return false;
	}
	g_Detour_CBaseServer__RejectConnection->EnableDetour();

	g_Detour_CBaseServer__CheckChallengeType = DETOUR_CREATE_MEMBER(CBaseServer__CheckChallengeType, "CBaseServer__CheckChallengeType");
	if(!g_Detour_CBaseServer__CheckChallengeType)
	{
		snprintf(error, maxlen, "Failed to detour CBaseServer__CheckChallengeType.\n");
		return false;
	}
	g_Detour_CBaseServer__CheckChallengeType->EnableDetour();

	g_Detour_CSteam3Server__OnValidateAuthTicketResponse = DETOUR_CREATE_MEMBER(CSteam3Server__OnValidateAuthTicketResponse, "CSteam3Server__OnValidateAuthTicketResponse");
	if(!g_Detour_CSteam3Server__OnValidateAuthTicketResponse)
	{
		snprintf(error, maxlen, "Failed to detour CSteam3Server__OnValidateAuthTicketResponse.\n");
		return false;
	}
	g_Detour_CSteam3Server__OnValidateAuthTicketResponse->EnableDetour();

	g_pConnectForward = g_pForwards->CreateForward("OnClientPreConnectEx", ET_LowEvent, 5, NULL, Param_String, Param_String, Param_String, Param_String, Param_String);

	return true;
}

bool Connect::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);
	ConVar_Register(0, this);

	return true;
}

void Connect::SDK_OnUnload()
{
	if(g_pConnectForward)
		g_pForwards->ReleaseForward(g_pConnectForward);

	if(g_Detour_CBaseServer__ConnectClient)
	{
		g_Detour_CBaseServer__ConnectClient->Destroy();
		g_Detour_CBaseServer__ConnectClient = NULL;
	}
	if(g_Detour_CBaseServer__RejectConnection)
	{
		g_Detour_CBaseServer__RejectConnection->Destroy();
		g_Detour_CBaseServer__RejectConnection = NULL;
	}
	if(g_Detour_CBaseServer__CheckChallengeType)
	{
		g_Detour_CBaseServer__CheckChallengeType->Destroy();
		g_Detour_CBaseServer__CheckChallengeType = NULL;
	}
	if(g_Detour_CSteam3Server__OnValidateAuthTicketResponse)
	{
		g_Detour_CSteam3Server__OnValidateAuthTicketResponse->Destroy();
		g_Detour_CSteam3Server__OnValidateAuthTicketResponse = NULL;
	}

	gameconfs->CloseGameConfigFile(g_pGameConf);
}

bool Connect::RegisterConCommandBase(ConCommandBase *pVar)
{
	/* Always call META_REGCVAR instead of going through the engine. */
	return META_REGCVAR(pVar);
}

cell_t ClientPreConnectEx(IPluginContext *pContext, const cell_t *params)
{
	char *pSteamID;
	pContext->LocalToString(params[1], &pSteamID);

	int retVal = params[2];

	char *rejectReason;
	pContext->LocalToString(params[3], &rejectReason);

	ConnectClientStorage Storage;
	if(!g_ConnectClientStorage.retrieve(pSteamID, &Storage))
		return 1;

	g_ConnectClientStorage.remove(pSteamID);

	g_lastClientSteamID = CSteamID(Storage.ullSteamID);

	if(retVal == 0)
	{
		RejectConnection(Storage.address, Storage.iClientChallenge, rejectReason);
		return 0;
	}

	g_bSuppressCheckChallengeType = true;
	DETOUR_MEMBER_MCALL_ORIGINAL(CBaseServer__ConnectClient, Storage.pThis)(Storage.address, Storage.nProtocol, Storage.iChallenge, Storage.iClientChallenge,
		Storage.nAuthProtocol, Storage.pchName, Storage.pchPassword, Storage.pCookie, Storage.cbCookie);

	// Make sure this is always called in order to verify the client on the server
	if(Storage.Validated)
		DETOUR_MEMBER_MCALL_ORIGINAL(CSteam3Server__OnValidateAuthTicketResponse, g_pSteam3Server)(&g_lastClientSteamID);

	return 0;
}

const sp_nativeinfo_t MyNatives[] =
{
	{ "ClientPreConnectEx", ClientPreConnectEx },
	{ NULL, NULL }
};

void Connect::SDK_OnAllLoaded()
{
	sharesys->AddNatives(myself, MyNatives);
}
