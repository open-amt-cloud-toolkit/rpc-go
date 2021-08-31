/*********************************************************************
* Copyright (c) Intel Corporation 2011 - 2020
* SPDX-License-Identifier: Apache-2.0
**********************************************************************/

/*
Real LMS code can be found here: http://software.intel.com/en-us/articles/download-the-latest-intel-amt-open-source-drivers
*/

#if !defined(_NOHECI)

#if defined(WIN32)  && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#else
#include <stdlib.h>
#endif

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2ipdef.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
#endif

#include "ILibParsers.h"
#include "ILibAsyncSocket.h"
#include "ILibAsyncServerSocket.h"

#ifdef WIN32
    #include "../heci/heciwin.h"
	#include "WinBase.h"
#endif
#ifdef _POSIX
    #include "../heci/HECILinux.h"
	#define UNREFERENCED_PARAMETER(P) (P)
#endif
#include "../heci/PTHICommand.h"
#include "../heci/LMEConnection.h"

#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))
#define LMS_MAX_CONNECTIONS 16 // Maximum is 32
#define LMS_MAX_SESSIONS 32
// #define _DEBUGLMS
#ifdef _DEBUGLMS
#define LMSDEBUG(...) printf(__VA_ARGS__);
#else
#define LMSDEBUG(...)
#endif

char * g_SelfLMSDir=NULL;
int LastId = 2;

struct ILibLMS_StateModule* IlibExternLMS = NULL;	// Glocal pointer to the LMS module. Since we can only have one of these modules running, a global pointer is sometimes useful.
void ILibLMS_SetupConnection(struct ILibLMS_StateModule* module, int i);
void ILibLMS_LaunchHoldingSessions(struct ILibLMS_StateModule* module);

// Each LMS session can be in one of these states.
enum LME_CHANNEL_STATUS {
	LME_CS_FREE = 0,						// The session slot is free, can be used at any time.
	LME_CS_PENDING_CONNECT = 1,				// A connection as been made to LMS and a notice has been send to Intel AMT asking for a CHANNEL OPEN.
	LME_CS_CONNECTED = 2,					// Intel AMT confirmed the connection and data can flow in both directions.
	LME_CS_PENDING_LMS_DISCONNECT = 3,		// The connection to LMS was disconnected, Intel AMT has been notified and we are waitting for Intel AMT confirmation.
	LME_CS_PENDING_AMT_DISCONNECT = 4,		// Intel AMT decided to close the connection. We are disconnecting the LMS TCP connection.
	LME_CS_HOLDING = 5,						// We got too much data from the LMS TCP connection, more than Intel AMT can handle. We are holding the connection until AMT can handle more.
	LME_CS_CONNECTION_WAIT = 6				// A TCP connection to LMS was made, but there all LMS connections are currently busy. Waitting for one to free up.
};

// This is the structure for a session
struct LMEChannel
{
	int ourid;								// The iddentifier of this channel on our side, this is the same as the index in the "Channel Sessions[LMS_MAX_SESSIONS];" array below.
	int amtid;								// The Intel AMT identifier for this channel.
	enum LME_CHANNEL_STATUS status;			// Current status of the channel.
	int sockettype;							// Type of connected socket: 0 = TCP, 1 = WebSocket
	void* socketmodule;						// The microstack associated with the LMS connection.
	int txwindow;							// Transmit window.
	int rxwindow;							// Receive window.
	unsigned short localport;				// The Intel AMT connection port.
	int errorcount;							// Open channel error count.
	char* pending;							// Buffer pointing to pending data that needs to be sent to Intel AMT, used for websocket only.
	int pendingcount;						// Buffer pointing to pending data size that needs to be sent to Intel AMT, used for websocket only.
	int pendingptr;							// Pointer to start of the pending buffer.
};

enum LME_VERSION_HANDSHAKING {
	LME_NOT_INITIATED,
	LME_INITIATED,
	LME_AGREED
};

enum LME_SERVICE_STATUS {
	LME_NOT_STARTED,
	LME_STARTED
};

// This is the Intel AMT LMS chain module structure
struct ILibLMS_StateModule
{
	ILibChain_Link ChainLink;
	void *Server1;										// Microstack TCP server for port 16992
	void *Server2;										// Microstack TCP server for port 16993
	void *ControlSocket;								// Pointer to the LMS control web socket, NULL if not connected.

	struct LMEConnection MeConnection;					// The MEI connection structure
	struct LMEChannel Sessions[LMS_MAX_SESSIONS];		// List of sessions
	//ILibWebServer_ServerToken WebServer;				// LMS Web Server
	enum LME_VERSION_HANDSHAKING handshakingStatus;
	enum LME_SERVICE_STATUS pfwdService;
	unsigned int AmtProtVersionMajor;					// Intel AMT MEI major version
	unsigned int AmtProtVersionMinor;					// Intel AMT MEI minor version
	sem_t Lock;											// Global lock, this is needed because MEI listener is a different thread from the microstack thread
};

/*
// Convert a block of data to HEX
// The "out" must have (len*2)+1 free space.
char utils_HexTable[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
char* __fastcall util_tohex(char* data, int len, char* out)
{
	int i;
	char *p = out;
	if (data == NULL || len == 0) { *p = 0; return NULL; }
	for (i = 0; i < len; i++)
	{
		*(p++) = utils_HexTable[((unsigned char)data[i]) >> 4];
		*(p++) = utils_HexTable[((unsigned char)data[i]) & 0x0F];
	}
	*p = 0;
	return out;
}
*/

int GetFreeSlot(struct ILibLMS_StateModule* module){
	int i;
	int cur = LastId;
	// Look for an empty session
	for (i = 0; i < LMS_MAX_SESSIONS-3; i++) {
		cur++;
		if (cur >= LMS_MAX_SESSIONS){
			cur = 3;
		}
		if (module->Sessions[cur].status == LME_CS_FREE) {
			LastId = cur;
			return cur;
		}
	}
	return -1;
}

//int GetFreeSlot(struct ILibLMS_StateModule* module){
//	int i;
//	for (i = 0; i < LMS_MAX_SESSIONS - 3; i++) {
//		if (cur >= LMS_MAX_SESSIONS){
//			cur = 3;
//		}
//		if (module->Sessions[cur].status == LME_CS_FREE) {
//			LastId = cur;
//			return cur;
//		}
//	}
//	return -1;
//}

// This function is called each time a MEI message is received from Intel AMT
void ILibLMS_MEICallback(struct LMEConnection* lmemodule, void *param, void *rxBuffer, unsigned int len)
{
	struct ILibLMS_StateModule* module = (struct ILibLMS_StateModule*)param;
	int disconnects = 0; // This is a counter of how many sessions are freed up. We use this at the end to place HOLDING sessions into free slots.

	//ILibAsyncServerSocket_ServerModule newModule;
	//ILibLinkedList list;
	//void* node;
	//ILibTransport* curModule;

	// Happens when the chain is being destroyed, don't call anything chain related.
	if (rxBuffer == NULL) return;

	sem_wait(&(module->Lock));
	LMSDEBUG("ILibLMS_MEICallback %d\r\n", ((unsigned char*)rxBuffer)[0]);

	switch (((unsigned char*)rxBuffer)[0])
	{
	case APF_GLOBAL_REQUEST: // 80
		{
			
			int request = 0;
			unsigned char *pCurrent;
			APF_GENERIC_HEADER *pHeader = (APF_GENERIC_HEADER *)rxBuffer;

			pHeader->StringLength = ntohl(pHeader->StringLength);

			if (pHeader->StringLength == APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST) && memcmp(pHeader->String, APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST, APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST)) == 0) { request = 1; }
			else if (pHeader->StringLength == APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST) && memcmp(pHeader->String, APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST, APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST)) == 0) { request = 2; }
			else if (pHeader->StringLength == APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_UDP_SEND_TO) && memcmp(pHeader->String, APF_GLOBAL_REQUEST_STR_UDP_SEND_TO, APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_UDP_SEND_TO)) == 0) { request = 3; }


			if (request == 1 || request == 2)
			{
				int port = 0;
				unsigned int len2;
				unsigned int bytesRead = len;
				unsigned int hsize=0;
				if (request==1)
					hsize = sizeof(APF_GENERIC_HEADER) + APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST) + sizeof(UINT8);
				else if (request==2)
					hsize = sizeof(APF_GENERIC_HEADER) + APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST) + sizeof(UINT8);

				pCurrent = (unsigned char*)rxBuffer + hsize;
				bytesRead -= hsize;
				if (bytesRead < sizeof(unsigned int)) { 
					LME_Deinit(lmemodule); 
					sem_post(&(module->Lock)); 
					return; 
				}

				len2 = ntohl(*((unsigned int *)pCurrent));
				pCurrent += sizeof(unsigned int);
				if (bytesRead < (sizeof(unsigned int) + len2 + sizeof(unsigned int))) { 
					LME_Deinit(lmemodule); 
					sem_post(&(module->Lock)); 
					return; 
				}

				// addr = (char*)pCurrent;
				pCurrent += len2;
				port = ntohl(*((unsigned int *)pCurrent));

				if (request == 1)
				{
					//newModule = ILibCreateAsyncServerSocketModule(module->Chain, LMS_MAX_CONNECTIONS, port, 4096, 0, &ILibLMS_OnConnect, &ILibLMS_OnDisconnect, &ILibLMS_OnReceive, NULL, &ILibLMS_OnSendOK);
					//if (newModule){
					//	ILibAsyncServerSocket_SetTag(newModule, module);
					//	LME_TcpForwardReplySuccess(lmemodule, port);
					//}
					//else{
					//	LME_TcpForwardReplyFailure(lmemodule);
					//}

					// New forwarding request
					if (port == 16992 || port == 16993) 
						LME_TcpForwardReplySuccess(lmemodule, port); 
					else 
						LME_TcpForwardReplyFailure(lmemodule);
				}
				else
				{
					// Cancel a forwarding request



					//list = ILibGetModuleList(module->Chain);
					//node = ILibLinkedList_GetNode_Head(list);
					//while (node != NULL){
					//	curModule = (ILibTransport*)ILibLinkedList_GetDataFromNode(node);
					//	if (curModule->IdentifierFlags == ILibTransports_ILibAsyncServerSocket){
					//		if (ILibAsyncServerSocket_GetPortNumber(curModule)){
					//			ILibAsyncServerSocket_Close(curModule);
					//		}
					//	}
					//	node = ILibLinkedList_GetNextNode(node);
					//}
					

					LME_TcpForwardCancelReplySuccess(lmemodule);
				}
			}
			else if (request == 3)
			{
				// Send a UDP packet
				// TODO: Send UDP
			}
			else{
				// do nothing
			}
		}
		break;
	case APF_CHANNEL_OPEN: // (90) Sent by Intel AMT when a channel needs to be open from Intel AMT. This is not common, but WSMAN events are a good example of channel coming from AMT.
		{
			APF_GENERIC_HEADER *pHeader = (APF_GENERIC_HEADER *)rxBuffer;

			if (pHeader->StringLength == APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_DIRECT) && memcmp((char*)pHeader->String, APF_OPEN_CHANNEL_REQUEST_DIRECT, APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_DIRECT)) == 0)
			{
				unsigned int len2;
				unsigned char *pCurrent;
				struct LMEChannelOpenRequestMessage channelOpenRequest;

				if (len < sizeof(APF_GENERIC_HEADER) + ntohl(pHeader->StringLength) + 7 + (5 * sizeof(UINT32))) { LME_Deinit(lmemodule); sem_post(&(module->Lock)); return; }
				pCurrent = (unsigned char*)rxBuffer + sizeof(APF_GENERIC_HEADER) + APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_DIRECT);

				channelOpenRequest.ChannelType = APF_CHANNEL_DIRECT;
				channelOpenRequest.SenderChannel = ntohl(*((UINT32 *)pCurrent));
				pCurrent += sizeof(UINT32);
				channelOpenRequest.InitialWindow = ntohl(*((UINT32 *)pCurrent));
				pCurrent += 2 * sizeof(UINT32);
				len2 = ntohl(*((UINT32 *)pCurrent));
				pCurrent += sizeof(UINT32);
				channelOpenRequest.Address = (char*)pCurrent;
				pCurrent += len2;
				channelOpenRequest.Port = ntohl(*((UINT32 *)pCurrent));
				pCurrent += sizeof(UINT32);

				LME_ChannelOpenReplyFailure(lmemodule, channelOpenRequest.SenderChannel, OPEN_FAILURE_REASON_CONNECT_FAILED);
			}
		}
		break;
	case APF_DISCONNECT: // (1) Intel AMT wants to completely disconnect. Not sure when this happens.
		{
			// First, we decode the message.
			struct LMEDisconnectMessage disconnectMessage;
			disconnectMessage.MessageType = APF_DISCONNECT;
			disconnectMessage.ReasonCode = ((APF_DISCONNECT_REASON_CODE)ntohl(((APF_DISCONNECT_MESSAGE *)rxBuffer)->ReasonCode));
			LMSDEBUG("LME requested to disconnect with reason code 0x%08x\r\n", disconnectMessage.ReasonCode);
			LME_Deinit(lmemodule);
		}
		break;
	case APF_SERVICE_REQUEST: // (5)
		{
			
			int service = 0;
			APF_SERVICE_REQUEST_MESSAGE *pMessage = (APF_SERVICE_REQUEST_MESSAGE *)rxBuffer;
			pMessage->ServiceNameLength = ntohl(pMessage->ServiceNameLength);
			if (pMessage->ServiceNameLength == 18) {
				if (memcmp(pMessage->ServiceName, "pfwd@amt.intel.com", 18) == 0) service = 1;
				else if (memcmp(pMessage->ServiceName, "auth@amt.intel.com", 18) == 0) service = 2;
			}

			if (service > 0)
			{
				if (service == 1)
				{
					LME_ServiceAccept(lmemodule, "pfwd@amt.intel.com");
					module->pfwdService = LME_STARTED;
				}
				else if (service == 2)
				{
					LME_ServiceAccept(lmemodule, "auth@amt.intel.com");
				}
			} else {
				LMSDEBUG("APF_SERVICE_REQUEST - APF_DISCONNECT_SERVICE_NOT_AVAILABLE\r\n");
				LME_Disconnect(lmemodule, APF_DISCONNECT_SERVICE_NOT_AVAILABLE);
				LME_Deinit(lmemodule);
				sem_post(&(module->Lock)); 
				return;
			}
		}
		break;
	case APF_CHANNEL_OPEN_CONFIRMATION: // (91) Intel AMT confirmation to an APF_CHANNEL_OPEN request.
		{
			
			// First, we decode the message.
			struct LMEChannel* channel;
			APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE *pMessage = (APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE *)rxBuffer;
			

			struct LMEChannelOpenReplySuccessMessage channelOpenReply;
			channelOpenReply.RecipientChannel = ntohl(pMessage->RecipientChannel);				// This is the identifier on our side.
			channelOpenReply.SenderChannel = ntohl(pMessage->SenderChannel);					// This is the identifier on the Intel AMT side.
			channelOpenReply.InitialWindow = ntohl(pMessage->InitialWindowSize);				// This is the starting window size for flow control.
			channel = &(module->Sessions[channelOpenReply.RecipientChannel]);					// Get the current session for this message.

			if (channel == NULL) 
				break;															// This should never happen.

			LMSDEBUG("MEI OPEN OK OUR:%d AMT:%d\r\n", channelOpenReply.RecipientChannel, channelOpenReply.SenderChannel);

			if (channel->status == LME_CS_PENDING_CONNECT)										// If the channel is in PENDING_CONNECT mode, move the session to connected state.
			{
				channel->amtid = channelOpenReply.SenderChannel;								// We have to set the Intel AMT identifier for this session.
				channel->txwindow = channelOpenReply.InitialWindow;								// Set the session txwindow.
				channel->status = LME_CS_CONNECTED;												// Now set the session as CONNECTED.
				LMSDEBUG("Channel %d now CONNECTED by AMT %d\r\n", channel->ourid, channel->socketmodule);
				if (channel->sockettype == 0)													// If the current socket is PAUSED, lets resume it so data can start flowing again.
				{
					ILibAsyncSocket_Resume(channel->socketmodule);								// TCP socket resume
				}
			}
			else if (channel->status == LME_CS_PENDING_LMS_DISCONNECT)							// If the channel is in PENDING_DISCONNECT, we have to disconnect the session now. Happens when we disconnect while connection is pending. We don't want to stop a channel during connection, that is bad.
			{
				channel->amtid = channelOpenReply.SenderChannel;								// We have to set the Intel AMT identifier for this session.
				LME_ChannelClose(&(module->MeConnection), channel->amtid, channel->ourid);		// Send the Intel AMT close. We keep the channel in LME_CS_PENDING_LMS_DISCONNECT state until the close is confirmed.
				LMSDEBUG("Channel %d now CONNECTED by AMT %d, but CLOSING it now\r\n", channel->ourid, channel->socketmodule);
			}
			else
			{
				// Here, we get an APF_CHANNEL_OPEN in an unexpected state, this should never happen.
				LMSDEBUG("Channel %d, unexpected CONNECTED by AMT %d\r\n", channel->ourid, channel->socketmodule);
			}
		}
		break;
	case APF_CHANNEL_OPEN_FAILURE: // (92) Intel AMT rejected our connection attempt.
		{
			
			// First, we decode the message.
			struct LMEChannel* channel;
			APF_CHANNEL_OPEN_FAILURE_MESSAGE *pMessage = (APF_CHANNEL_OPEN_FAILURE_MESSAGE *)rxBuffer;
			struct LMEChannelOpenReplyFailureMessage channelOpenReply;
			channelOpenReply.RecipientChannel = ntohl(pMessage->RecipientChannel);				// This is the identifier on our side.

			channelOpenReply.ReasonCode = (OPEN_FAILURE_REASON)(ntohl(pMessage->ReasonCode));	// Get the error reason code.
			channel = &(module->Sessions[channelOpenReply.RecipientChannel]);					// Get the current session for this message.
			if (channel == NULL) break;															// This should never happen.

			LMSDEBUG("**OPEN FAIL OUR:%d ERR:%d\r\n", channelOpenReply.RecipientChannel, channelOpenReply.ReasonCode);

			if (channel->errorcount++ >= 0 || channel->status == LME_CS_PENDING_LMS_DISCONNECT)
			{
				// Fail connection
				channel->status = LME_CS_FREE;
				LMSDEBUG("Channel %d now FREE by AMT\r\n", channel->ourid);
				sem_post(&(module->Lock));
				ILibAsyncSocket_Disconnect(channel->socketmodule);
				//ILibLMS_LaunchHoldingSessions(module);
				return;
			}
			else
			{
				// Try again
				//ILibLMS_SetupConnection(module, channel->ourid);
			}
		}
		break;
	case APF_CHANNEL_CLOSE: // (97) Intel AMT is closing this channel, we need to disconnect the LMS TCP connection
		{
			
			// First, we decode the message.
			struct LMEChannel* channel;
			APF_CHANNEL_CLOSE_MESSAGE *pMessage = (APF_CHANNEL_CLOSE_MESSAGE *)rxBuffer;
			struct LMEChannelCloseMessage channelClose;
			channelClose.RecipientChannel = ntohl(pMessage->RecipientChannel);					// This is the identifier on our side.
			channel = &(module->Sessions[channelClose.RecipientChannel]);						// Get the current session for this message.
			if (channel == NULL) break;															// This should never happen.

			//LMSDEBUG("CLOSE OUR:%d\r\n", channelClose.RecipientChannel);

			if (channel->status == LME_CS_CONNECTED)
			{
				if (ILibAsyncSocket_IsConnected(channel->socketmodule))
				{
					channel->status = LME_CS_PENDING_AMT_DISCONNECT;
					LMSDEBUG("Channel %d now PENDING_AMT_DISCONNECT by AMT, calling microstack disconnect %d\r\n", channel->ourid, channel->socketmodule);
					LME_ChannelClose(lmemodule, channel->amtid, channel->ourid);
					sem_post(&(module->Lock));
					if (channel->sockettype == 0)													// If the current socket is PAUSED, lets resume it so data can start flowing again.
					{
						ILibAsyncSocket_Disconnect(channel->socketmodule);							// TCP socket close
					}

					sem_wait(&(module->Lock));
					channel->status = LME_CS_FREE;
					disconnects++;
					LMSDEBUG("Channel %d now FREE by AMT\r\n", channel->ourid);
				}
				else
				{
					channel->status = LME_CS_FREE;
					disconnects++;
					LMSDEBUG("Channel %d now FREE by AMT\r\n", channel->ourid);
				}
			}
			else if (channel->status == LME_CS_PENDING_LMS_DISCONNECT)
			{
				channel->status = LME_CS_FREE;
				disconnects++;
				LMSDEBUG("Channel %d now FREE by AMT\r\n", channel->ourid);
			}
			else
			{
				LMSDEBUG("Channel %d CLOSE, UNEXPECTED STATE %d\r\n", channel->ourid, channel->status);
			}
		}
		break;
	case APF_CHANNEL_DATA: // (94) Intel AMT is sending data that we must relay into an LMS TCP connection.
		{
			//sem_wait(&(module->Lock));

			struct LMEChannel* channel;
			APF_CHANNEL_DATA_MESSAGE *pMessage = (APF_CHANNEL_DATA_MESSAGE *)rxBuffer;
			struct LMEChannelDataMessage channelData;
			enum ILibAsyncSocket_SendStatus r;
			channelData.MessageType = APF_CHANNEL_DATA;
			channelData.RecipientChannel = ntohl(pMessage->RecipientChannel);
			channelData.DataLength = ntohl(pMessage->DataLength);
			channelData.Data = (unsigned char*)rxBuffer + sizeof(APF_CHANNEL_DATA_MESSAGE);
			channel = &(module->Sessions[channelData.RecipientChannel]);


			if (channel == NULL || channel->socketmodule == NULL){
				sem_post(&(module->Lock));
				break;
			}

			if (channel->sockettype == 0)
			{
				r = ILibAsyncSocket_Send(channel->socketmodule, (char*)(channelData.Data), channelData.DataLength, ILibAsyncSocket_MemoryOwnership_USER); // TCP socket
			}
			
			channel->rxwindow += channelData.DataLength;
			if (r == ILibAsyncSocket_ALL_DATA_SENT && channel->rxwindow > 1024) { 
				LME_ChannelWindowAdjust(lmemodule, channel->amtid, channel->rxwindow); channel->rxwindow = 0; 
			}
			//sem_post(&(module->Lock));
		}
		break;
	case APF_CHANNEL_WINDOW_ADJUST: // 93
		{
			//sem_wait(&(module->Lock));

			struct LMEChannel* channel;
			APF_WINDOW_ADJUST_MESSAGE *pMessage = (APF_WINDOW_ADJUST_MESSAGE *)rxBuffer;
			struct LMEChannelWindowAdjustMessage channelWindowAdjust;
			channelWindowAdjust.MessageType = APF_CHANNEL_WINDOW_ADJUST;
			channelWindowAdjust.RecipientChannel = ntohl(pMessage->RecipientChannel);
			channelWindowAdjust.BytesToAdd = ntohl(pMessage->BytesToAdd);
			channel = &(module->Sessions[channelWindowAdjust.RecipientChannel]);
			if (channel == NULL || channel->status == LME_CS_FREE){
				sem_post(&(module->Lock));
				break;
			}
			channel->txwindow += channelWindowAdjust.BytesToAdd;
			if (channel->sockettype == 0)
			{
				ILibAsyncSocket_Resume(channel->socketmodule); // TCP socket
			}
			//sem_post(&(module->Lock));
		}
		break;
	case APF_PROTOCOLVERSION: // 192
		{
			APF_PROTOCOL_VERSION_MESSAGE *pMessage = (APF_PROTOCOL_VERSION_MESSAGE *)rxBuffer;
			struct LMEProtocolVersionMessage protVersion;
			protVersion.MajorVersion = ntohl(pMessage->MajorVersion);
			protVersion.MinorVersion = ntohl(pMessage->MinorVersion);
			protVersion.TriggerReason = (APF_TRIGGER_REASON)ntohl(pMessage->TriggerReason);

			switch (module->handshakingStatus)
			{
			case LME_AGREED:
			case LME_NOT_INITIATED:
				{
					LME_ProtocolVersion(lmemodule, 1, 0, protVersion.TriggerReason);
				}
			case LME_INITIATED:
				if (protVersion.MajorVersion != 1 || protVersion.MinorVersion != 0)
				{
					LMSDEBUG("LME Version %d.%d is not supported.\r\n", protVersion.MajorVersion, protVersion.MinorVersion);
					LME_Disconnect(lmemodule, APF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
					LME_Deinit(lmemodule);
					sem_post(&(module->Lock)); 
					return;
				}
				module->AmtProtVersionMajor = protVersion.MajorVersion;
				module->AmtProtVersionMinor = protVersion.MinorVersion;
				module->handshakingStatus = LME_AGREED;
				break;
			default:
				LME_Disconnect(lmemodule, APF_DISCONNECT_BY_APPLICATION);
				LME_Deinit(lmemodule);
				break;
			}
		}
		break;
	case APF_USERAUTH_REQUEST: // 50
		{
			// _lme.UserAuthSuccess();
		}
		break;
	default:
		// Unknown request.
		LMSDEBUG("**Unknown LME command: %d\r\n", ((unsigned char*)rxBuffer)[0]);
		LME_Disconnect(lmemodule, APF_DISCONNECT_PROTOCOL_ERROR);
		LME_Deinit(lmemodule);
		break;
	}

	sem_post(&(module->Lock));
	//if (disconnects > 0) ILibLMS_LaunchHoldingSessions(module); // If disconnects is set to anything, we have free session slots we can fill up.
}

void ILibLMS_OnReceive(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncServerSocket_OnInterrupt *OnInterrupt, void **user, int *PAUSE)
{
	int r, maxread = endPointer;
	struct ILibLMS_StateModule* module = (struct ILibLMS_StateModule*)ILibAsyncServerSocket_GetTag(AsyncServerSocketModule);
	struct LMEChannel* channel = (struct LMEChannel*)*user;

	UNREFERENCED_PARAMETER( AsyncServerSocketModule );
	UNREFERENCED_PARAMETER( ConnectionToken );
	UNREFERENCED_PARAMETER( OnInterrupt );
	UNREFERENCED_PARAMETER( PAUSE );

	if (channel == NULL) return;
	sem_wait(&(module->Lock)); 
	if (channel->socketmodule != ConnectionToken) { sem_post(&(module->Lock)); ILibAsyncSocket_Disconnect(ConnectionToken); return; }
	if (channel->txwindow < endPointer) maxread = channel->txwindow;
	if (channel->status != LME_CS_CONNECTED || maxread == 0) { *PAUSE = 1; sem_post(&(module->Lock)); return; }
	//printf("%.*s", maxread, buffer);
	r = LME_ChannelData(&(module->MeConnection), channel->amtid, maxread, (unsigned char*)buffer);
	//LMSDEBUG("ILibLMS_OnReceive, status = %d, txwindow = %d, endPointer = %d, r = %d\r\n", channel->status, channel->txwindow, endPointer, r);
	if (r != maxread)
	{
		//LMSDEBUG("ILibLMS_OnReceive, DISCONNECT %d\r\n", channel->ourid);
		sem_post(&(module->Lock));
		ILibAsyncSocket_Disconnect(ConnectionToken); // Drop the connection
		return;
	}
	channel->txwindow -= maxread;
	*p_beginPointer = maxread;
	sem_post(&(module->Lock)); 
}

void ILibLMS_SetupConnection(struct ILibLMS_StateModule* module, int i)
{
	int rport = 0;
	char* laddr = NULL;
	struct sockaddr_in6 remoteAddress;

	if (module->Sessions[i].sockettype == 0)
	{
		// Fetch the socket remote TCP address
		ILibAsyncSocket_GetRemoteInterface(module->Sessions[i].socketmodule, (struct sockaddr*)&remoteAddress);
		if (remoteAddress.sin6_family == AF_INET6)
		{
			laddr = "::1"; // TODO: decode this properly into a string
			rport = ntohs(remoteAddress.sin6_port);
		}
		else
		{
			laddr = "127.0.0.1"; // TODO: decode this properly into a string
			rport = ntohs(((struct sockaddr_in*)(&remoteAddress))->sin_port);
		}
	}
	else
	{
		// Fetch the socket remote web socket address
		laddr = "127.0.0.1"; // TODO: decode this properly into a string
		rport = 123; // TODO: decode the remote port
	}

	// Setup a new LME session
	LME_ChannelOpenForwardedRequest(&(module->MeConnection), (unsigned int)i, laddr, module->Sessions[i].localport, laddr, rport);
	//LMSDEBUG("ILibLMS_OnReceive, CONNECT %d\r\n", i);
}


int OnConnect = 0;
void ILibLMS_OnConnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void **user)
{
	OnConnect++;
	LMSDEBUG("OnCOnnect:%d", OnConnect);
	int i, sessionid = -1, activecount = 0;
	struct ILibLMS_StateModule* module = (struct ILibLMS_StateModule*)ILibAsyncServerSocket_GetTag(AsyncServerSocketModule);

	sem_wait(&(module->Lock));

	// Count the number of active sessions
	activecount = LMS_MAX_SESSIONS;
	for (i = 0; i < LMS_MAX_SESSIONS; i++) { 
		if (module->Sessions[i].status == LME_CS_FREE || module->Sessions[i].status == LME_CS_CONNECTION_WAIT) { 
			activecount--; 
		} 
	}
	
	sessionid=GetFreeSlot(module);
	
	// Look for an empty session
	//for (i = 1; i < LMS_MAX_SESSIONS; i++) { 
	//	if (module->Sessions[i].status == LME_CS_FREE) { 
	//		sessionid = i;
	//		break; 
	//	} 
	//}
	if (sessionid == -1)
	{
		sem_post(&(module->Lock)); 
		LMSDEBUG("ILibLMS_OnConnect NO SESSION SLOTS AVAILABLE\r\n");
		ILibAsyncSocket_Disconnect(ConnectionToken); // Drop the connection
		return;
	}
	i = sessionid;

	// LMSDEBUG("USING SLOT OUR:%d\r\n", i);
	module->Sessions[i].amtid = -1;
	module->Sessions[i].ourid = i;
	module->Sessions[i].sockettype = 0; // TCP Type
	module->Sessions[i].socketmodule = ConnectionToken;
	module->Sessions[i].rxwindow = 0;
	module->Sessions[i].txwindow = 0;
	module->Sessions[i].localport = ILibAsyncServerSocket_GetPortNumber(AsyncServerSocketModule);
	module->Sessions[i].errorcount = 0;
	*user = &(module->Sessions[i]);

	/*
	if (activecount >= LMS_MAX_CONNECTIONS)
	{
		module->Sessions[i].status = LME_CS_CONNECTION_WAIT;
		LMSDEBUG("ILibLMS_OnConnect %d (HOLDING)\r\n", i);
	}
	else
	*/
	{
		module->Sessions[i].status = LME_CS_PENDING_CONNECT;
		LMSDEBUG("ILibLMS_OnConnect %d\r\n", i);
		ILibLMS_SetupConnection(module, i);
	}

	sem_post(&(module->Lock));
}

void ILibLMS_OnDisconnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
	int disconnects = 0;
	struct ILibLMS_StateModule* module = (struct ILibLMS_StateModule*)ILibAsyncServerSocket_GetTag(AsyncServerSocketModule);
	struct LMEChannel* channel = (struct LMEChannel*)user;
	UNREFERENCED_PARAMETER( ConnectionToken );

	sem_wait(&(module->Lock)); 

	if (channel == NULL || channel->socketmodule != ConnectionToken)
	{
		LMSDEBUG("****ILibLMS_OnDisconnect EXIT\r\n");
		sem_post(&(module->Lock));
		return;
	}

	LMSDEBUG("ILibLMS_OnDisconnect, Channel %d, %d\r\n", channel->ourid, ConnectionToken);

	if (channel->status == LME_CS_CONNECTED)
	{
		channel->status = LME_CS_PENDING_LMS_DISCONNECT;
		if (channel->amtid!=-1 && !LME_ChannelClose(&(module->MeConnection), channel->amtid, channel->ourid))
		{
			channel->status = LME_CS_FREE;
			disconnects++;
			LMSDEBUG("Channel %d now FREE by LMS because of failed close\r\n", channel->ourid);
		}
		else
		{
			LMSDEBUG("Channel %d now PENDING_LMS_DISCONNECT by LMS\r\n", channel->ourid);
			//LMSDEBUG("LME_ChannelClose OK\r\n");
		}
	}
	else if (channel->status == LME_CS_PENDING_CONNECT)
	{
		channel->status = LME_CS_PENDING_LMS_DISCONNECT;
		LMSDEBUG("Channel %d now PENDING_DISCONNECT by LMS\r\n", channel->ourid);
	}
	else if (channel->status == LME_CS_CONNECTION_WAIT)
	{
		channel->status = LME_CS_FREE;
		disconnects++;
		LMSDEBUG("Channel %d now FREE by LMS\r\n", channel->ourid);
	}
	//LMSDEBUG("ILibLMS_OnDisconnect, DISCONNECT %d, status = %d\r\n", channel->ourid, channel->status);
	sem_post(&(module->Lock));
	
	//if (disconnects > 0) ILibLMS_LaunchHoldingSessions(module);
}

void ILibLMS_OnSendOK(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
	struct ILibLMS_StateModule* module = (struct ILibLMS_StateModule*)ILibAsyncServerSocket_GetTag(AsyncServerSocketModule);
	struct LMEChannel* channel = (struct LMEChannel*)user;
	UNREFERENCED_PARAMETER( ConnectionToken );

	// Ok to send more on this socket, adjust the window
	sem_wait(&(module->Lock)); 
	if (channel->rxwindow != 0)
	{
		//LMSDEBUG("LME_ChannelWindowAdjust id=%d, rxwindow=%d\r\n", channel->amtid, channel->rxwindow);
		LME_ChannelWindowAdjust(&(module->MeConnection), channel->amtid, channel->rxwindow);
		channel->rxwindow = 0;
	}
	sem_post(&(module->Lock));
}
// Private method called when the chain is destroyed, we want to do our cleanup here
void ILibLMS_Destroy(void *object)
{
	struct ILibLMS_StateModule* module = (struct ILibLMS_StateModule*)object;
	UNREFERENCED_PARAMETER( object );

	sem_wait(&(module->Lock)); 
	LME_Disconnect(&(module->MeConnection), APF_DISCONNECT_BY_APPLICATION);
	LME_Exit(&(module->MeConnection));
	sem_destroy(&(module->Lock));
	if (IlibExternLMS == module) { IlibExternLMS = NULL; }	// Clear the global reference to the the LMS module.
}

// Create a new Reflector module.
struct ILibLMS_StateModule *ILibLMS_Create(void *Chain)
{
	struct ILibLMS_StateModule *module;

	// Allocate the new module
	module = (struct ILibLMS_StateModule*)malloc(sizeof(struct ILibLMS_StateModule));
	if (module == NULL) { ILIBCRITICALEXIT(254); }	
	memset(module, 0, sizeof(struct ILibLMS_StateModule));

	// Setup MEI with LMS interface, if we can't return null
	if (LME_Init(&(module->MeConnection), &ILibLMS_MEICallback, module) == 0) { 
		free(module); 
		return NULL; 
	}

	// Setup the module
	module->ChainLink.DestroyHandler = &ILibLMS_Destroy;
	module->ChainLink.ParentChain = Chain;
	sem_init(&(module->Lock), 0, 1);

	// TCP servers
	module->Server1 = ILibCreateAsyncServerSocketModule(Chain, LMS_MAX_CONNECTIONS, 16992, 4096, 0, &ILibLMS_OnConnect, &ILibLMS_OnDisconnect, &ILibLMS_OnReceive, NULL, &ILibLMS_OnSendOK);
	if (module->Server1 == NULL) { sem_destroy(&(module->Lock)); free(module); return NULL; }
	ILibAsyncServerSocket_SetTag(module->Server1, module);

	module->Server2 = ILibCreateAsyncServerSocketModule(Chain, LMS_MAX_CONNECTIONS, 16993, 4096, 0, &ILibLMS_OnConnect, &ILibLMS_OnDisconnect, &ILibLMS_OnReceive, NULL, &ILibLMS_OnSendOK);
	if (module->Server2 == NULL) { sem_destroy(&(module->Lock)); free(module->Server1); free(module); return NULL; }
	ILibAsyncServerSocket_SetTag(module->Server2, module);

	


	// TODO: US6986 - The meshcommander site should not be served on localhost:16994.
	// This code should be commented out - in the future(late 2018) IMC could be put there instead.
	// Web Server
	//module->WebServer = ILibWebServer_CreateEx(Chain, 8, 16994, 2, &ILibLMS_WebServer_OnSession, module);

	IlibExternLMS = module;						// Set the global reference to the LMS module.
	ILibAddToChain(Chain, module);				// Add this module to the chain.
	return module;
}

#endif
