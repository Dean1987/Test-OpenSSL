#ifndef _LES_SSL_STRUCT_H
#define _LES_SSL_STRUCT_H
#include "../Header.h"

typedef struct 
{
	char* strServerName;
	char* strCertificateFile;
	char* strPrivateKey;
	char* strOptionalChainFile;
}Certificate;

struct _LES_SSL_Context
{
	/**
	* @internal Controls logs output..
	*/
	/* context reference counting */
	int nRefs;

	/* console log */
	bool bNot_executed;
	bool bDebug_enabled;

	/* colored log */
	bool bNot_executed_color;
	bool bDebug_color_enabled;

	bool bKeep_looping;

	/**
	* @internal Conn connection timeout.
	*/
	long  lConn_connect_std_timeout;

	/**
	* @internal Default listener connection backlog
	*/
	int nBacklog;

	/**
	* @internal Currently selected io engine on this context.
	*/
	LES_SSL_IoEngine* pIo_engine;

	/**
	* @internal Connection array list and its length.
	*/
	int nConn_id;
	LES_SSL_Conn** pConn_list;
	int nConn_length;
	/**
	* @internal Number of connections registered on this context.
	*/
	int nConn_num;

	/**
	* @internal Reference to defined on accept handling.
	*/
	ActionHandler pOn_accept;
	voidPtr pOn_accept_data;

	/**
	* @internal Reference to defined on ready handling.
	*/
	ActionHandler pOn_ready;
	voidPtr pOn_ready_data;

	/**
	* @internal Reference to defined on open handling.
	*/
	ActionHandler pOn_open;
	voidPtr pOn_open_data;

	/**
	* @internal Reference to the defined on message handling.
	*/
	OnMessageHandler pOn_msg;
	voidPtr pOn_msg_data;

	/**
	* @internal Basic fake support for protocol version, by
	* default: 13, due to RFC6455 standard
	*/
	int nProtocol_version;

	/**
	* @internal Certificates added..
	*/
	Certificate*  pCertificates;
	int nCertificates_length;

	/* mutex */
	voidPtr pRef_mutex;

	/* log handling */
	//LogHandler sLog_handler;
	voidPtr pLog_user_data;

	/* context creator */
	//SslContextCreator sContext_creator;
	voidPtr pContext_creator_data;

	/* SSL postcheck */
	//SslPostCheck sPost_ssl_check;
	voidPtr pPost_ssl_check_data;
};

struct _LES_SSL_Conn
{
	/**
	* @internal Connection id.
	*/
	int nId;

	/**
	* @internal The context associated to this connection.
	*/
	LES_SSL_Context* pCtx;

	/**
	* @internal This is the actual socket handler associated to
	* the noPollConn object.
	*/
	SOCKET sSession;
	/**
	* @internal Flag to signal this connection has finished its
	* handshake.
	*/
	bool bHandshake_ok;

	/**
	* @internal Current connection receive function.
	*/
	LES_SSL_Read pReceive;

	/**
	* @internal Current connection receive function.
	*/
	LES_SSL_Read pSend;

	/**
	* @internal The connection role.
	*/
	LES_SSL_Role nRole;

	/**
	* @internal Conection host ip location (connecting or listening).
	*/
	char* strHost;

	/**
	* @internal Connection port location (connecting or
	* listening).
	*/
	char* strPort;

	/**
	* @internal Host name requested on the connection.
	*/
	char* strHost_name;
	/**
	* @internal Origin requested on the connection.
	*/
	char* strOrigin;

	/**
	* @internal reference to the get url.
	*/
	char* strGet_url;

	/**
	* @internal Reference to protocols requested to be opened on
	* this connection.
	*/
	char* strProtocols;
	/* @internal reference to the protocol that was replied by the server */
	char* strAccepted_protocol;

	/* close status and reason */
	int nPeer_close_status;
	char* strPeer_close_reason;

	/**
	* @internal Reference to the defined on message handling.
	*/
	OnMessageHandler pOn_msg;
	voidPtr pOn_msg_data;

	/**
	* @internal Reference to defined on ready handling.
	*/
	ActionHandler pOn_ready;
	voidPtr pOn_ready_data;

	/**
	* @internal Reference to the defined on close handling.
	*/
	OnCloseHandler oOn_close;
	voidPtr pOn_close_data;

	/* reference to the handshake */
	LES_SSL_Handshake* pHandshake;

	/* reference to a buffer with pending content */
	char* strPending_line;

	/**
	* @internal connection reference counting.
	*/
	int nRefs;

	/**
	* @internal References to pending content to be read
	*/
	LES_SSL_Msg* pPending_msg;
	long int lPending_diff;
	long int lPending_desp;

	/**
	* @internal Flag to handle TLS support upon connection
	* reception.
	*/
	bool bTls_on;
	/**
	* @internal Flag that indicates that the provided session
	* must call to accept the TLS session before proceeding.
	*/
	bool bPending_ssl_accept;

	/* SSL support */
	SSL_CTX* pSsl_ctx;
	SSL* pSsl;

	/* certificates */
	char* strCertificate;
	char* strPrivate_key;
	char* strChain_certificate;

	/* pending buffer */
	char strPending_buf[100];
	int nPending_buf_bytes;

	/**
	* @internal Support for an user defined pointer.
	*/
	voidPtr pHook;

	/**
	* @internal Mutex
	*/
	voidPtr pRef_mutex;

	/**
	* @internal Variable to track pending bytes from previous
	* read that must be completed.
	*/
	LES_SSL_Msg* pPrevious_msg;
	/* allows to track if previous message was a fragment to flag
	* next message, even having FIN enabled as a fragment. */
	bool bPrevious_was_fragment;

	char* strPending_write;
	int nPending_write_bytes;

	/**
	* @internal Internal reference to the connection options.
	*/
	LES_SSL_ConnOpts* pOpts;

	/**
	* @internal Reference to the listener in the case this is a
	* connection that was created due to a listener running.
	*/
	LES_SSL_Conn* pListener;
};

struct _IoEngine
{
	voidPtr pIo_object;
	LES_SSL_Context* pContext;
	IoMechCreate pMechCreate;
	IoMechDestroy pMechDestroy;
	IoMechClear pMechClear;
	IoMechWait pMechWait;
	IoMechAddTo pMechAddto;
	IoMechIsSet pMechIsset;
};

struct _LES_SSL_Msg
{
	bool bHas_fin;
	short sOp_code;
	bool bIs_masked;

	voidPtr pPayload;
	long int lPayload_size;

	int nRefs;
	voidPtr pRef_mutex;

	char strMask[4];
	int nRemain_bytes;

	bool bIs_fragment;
	int nUnmask_desp;
};

struct _LES_SSL_Handshake
{
	/**
	* @internal Reference to the to the GET url HTTP/1.1 header
	* part.
	*/
	bool bUpgrade_websocket;
	bool bConnection_upgrade;
	bool bReceived_101;
	char* strWebsocket_key;
	char* strWebsocket_version;
	char* strWebsocket_accept;
	char* strExpected_accept;

	/* reference to cookie header */
	char* strCookie;
};

struct _LES_SSL_ConnOpts
{
	/* If the connection options object should be reused across calls */
	bool bReuse;

	/* mutex */
	voidPtr pMutex;
	int nRefs;

	/* What ssl protocol should be used */
	SslProtocol nSsl_protocol;

	/* SSL options */
	char* strCertificate;
	char* strPrivate_key;
	char* strChain_certificate;
	char* strCa_certificate;

	bool bDisable_ssl_verify;

	/* cookie support */
	char* strCookie;
};
#endif