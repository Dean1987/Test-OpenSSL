#include "../Header.h"
#include "les_ssl_struct.h"
#include "les_ssl_handshake.h"
#include "les_ssl_conn.h"
#include "les_ssl_key.h"
#include "les_ssl_string.h"

bool les_ssl_handshake_check_listener( LES_SSL_Context* pCtx , LES_SSL_Conn* pConn )
{
	char* strReply = NULL;
	size_t nReply_size = 0;
	char* strAccept_key = NULL;
	ActionHandler pOn_ready = NULL;
	voidPtr pOn_ready_data = NULL;
	const char* strProtocol = NULL;

	/* call to check listener handshake */
	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE , "Checking client handshake data.." );

	/* ensure we have all minumum data */
	if( !pConn->pHandshake->bUpgrade_websocket ||
		!pConn->pHandshake->bConnection_upgrade ||
		!pConn->pHandshake->strWebsocket_key ||
		!pConn->strOrigin ||
		!pConn->pHandshake->strWebsocket_version )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Client from %s:%s didn't provide all websocket handshake values required, closing session (Upgraded: websocket %d, Connection: upgrade%d, "
			"Sec-WebSocket-Key: %p, Origin: %p, Sec-WebSocket-Version: %p)" ,
			pConn->strHost , pConn->strPort ,
			pConn->pHandshake->bUpgrade_websocket ,
			pConn->pHandshake->bConnection_upgrade ,
			pConn->pHandshake->strWebsocket_key ,
			pConn->strOrigin ,
			pConn->pHandshake->strWebsocket_version );
		return false;
	}

	/* check protocol support */
	if( strtod( pConn->pHandshake->strWebsocket_version , NULL ) != pCtx->nProtocol_version )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Received request for an unsupported protocol version: %s, expected: %d" ,
			pConn->pHandshake->strWebsocket_version , pCtx->nProtocol_version );
		return false;
	}

	/* now call the user app level to accept the websocket
	connection */
	if( pCtx->pOn_open )
	{
		if( !pCtx->pOn_open( pCtx , pConn , pCtx->pOn_open_data ) )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "Client from %s:%s was denied by application level (on open handler %p), clossing session" ,
				pConn->strHost , pConn->strPort , pCtx->pOn_open );
			les_ssl_conn_shutdown( pConn );
			return false;
		}
	} 

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Client from %s:%s was accepted, replying accept" ,
		pConn->strHost , pConn->strPort );

	/* produce accept key */
	strAccept_key = les_ssl_produce_accept_key( pCtx , pConn->pHandshake->strWebsocket_key );

	/* ok, send handshake reply */
	if( pConn->strProtocols || pConn->strAccepted_protocol )
	{
		/* set protocol in the reply taking preference by the
		value configured at conn->accepted_protocol */
		strProtocol = pConn->strAccepted_protocol;
		if( !strProtocol )
			strProtocol = pConn->strProtocols;

		/* send accept header accepting protocol requested by the user */
		strReply = les_ssl_printfv( "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n" ,
			strAccept_key , strProtocol );
	}
	else
	{
		/* send accept header without telling anything about protocols */
		strReply = les_ssl_printfv( "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n" ,
			strAccept_key );
	}

	free( strAccept_key );
	if( strReply == NULL )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Unable to build reply, closing session" );
		return false;
	} 

	nReply_size = strlen( strReply );
	if( nReply_size != pConn->pSend( pConn , strReply , nReply_size ) )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Unable to send reply, there was a failure, error code was: %d" , errno );
		free( strReply );
		return false;
	} 

	/* free reply */
	free( strReply );

	/* now call the user app level to accept the websocket
	connection */
	if( pCtx->pOn_ready || pConn->pOn_ready )
	{
		/* set on ready handler, first considering conn->on_ready and then ctx->on_ready */
		pOn_ready = pConn->pOn_ready;
		pOn_ready_data = pConn->pOn_ready_data;
		if( !pOn_ready )
		{
			pOn_ready = pCtx->pOn_ready;
			pOn_ready_data = pCtx->pOn_ready_data;
		} 

		if( pOn_ready &&  !pOn_ready( pCtx , pConn , pOn_ready_data ) )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "Client from %s:%s was denied by application level (on ready handler: %p), clossing session" 
				, pConn->strHost , pConn->strPort , pOn_ready );
			les_ssl_conn_shutdown( pConn );
			return false;
		}
	}

	return true; /* signal handshake was completed */
}

bool les_ssl_handshake_check_client( LES_SSL_Context* pCtx , LES_SSL_Conn* pConn )
{
	char* strAccept = NULL;
	bool bResult = false;

	/* check all data received */
	if( !pConn->pHandshake->strWebsocket_accept ||
		!pConn->pHandshake->bUpgrade_websocket ||
		!pConn->pHandshake->bConnection_upgrade )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Received uncomplete listener handshake reply (%p %d %d)" ,
			pConn->pHandshake->strWebsocket_accept , pConn->pHandshake->bUpgrade_websocket , pConn->pHandshake->bConnection_upgrade );
		return false;
	}

	 /* check accept value here */
	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE , "Checking accept key from listener.." );
	strAccept = les_ssl_produce_accept_key( pCtx , pConn->pHandshake->strWebsocket_key );

	bResult = strcmp( strAccept , pConn->pHandshake->strWebsocket_key ) == 0;
	if( !bResult )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Unable to accept connection Sec-Websocket-Accept %s is not expected %s, closing session" ,
			strAccept , pConn->pHandshake->strWebsocket_key );
		les_ssl_conn_shutdown( pConn );
	}
	free( strAccept );

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Sec-Websocket-Accept matches expected value..nopoll_conn_complete_handshake_check_client (%p, %p)=%d" 
		, pCtx , pConn , bResult );

	return bResult;
}

void les_ssl_handshake_check( LES_SSL_Conn* pConn )
{
	if( pConn == NULL )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Conn is NULL!" );
		return;
	}
	LES_SSL_Context* pCtx = pConn->pCtx;
	bool bResult = false;

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "calling to check handshake received on connection id %d role %d.." ,
		pConn->nId , pConn->nRole );

	if( pConn->nRole == LES_SSL_ROLE_LISTENER )
	{
		bResult = les_ssl_handshake_check_listener( pCtx , pConn );
	}
	else if( pConn->nRole == LES_SSL_ROLE_CLIENT )
	{
		bResult = les_ssl_handshake_check_client( pCtx , pConn );
	} 

	/* flag connection as ready: now we can get messages */
	if( bResult )
	{
		pConn->bHandshake_ok = true;
	}
	else
	{
		les_ssl_conn_shutdown( pConn );
	}

	return;
}
int les_ssl_complete_handshake_listener( LES_SSL_Context* pCctx , LES_SSL_Conn* pConn , char* strBuffer , int nBuffer_size )
{
	char* strHeader = NULL;
	char* strValue = NULL;

	/* handle content */
	if( les_ssl_ncmp( strBuffer , "GET " , 4 ) )
	{
		/* get url method */
		les_ssl_conn_get_http_url( pConn , strBuffer , nBuffer_size , "GET" , &pConn->strGet_url );
		return 1;
	} /* end if */

	  /* get mime header */
	if( !nopoll_conn_get_mime_header( ctx , conn , buffer , buffer_size , &header , &value ) )
	{
		nopoll_log( ctx , NOPOLL_LEVEL_CRITICAL , "Failed to acquire mime header from remote peer during handshake, closing connection" );
		nopoll_conn_shutdown( conn );
		return 0;
	}

	/* ok, process here predefined headers */
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Host" , conn->host_name ) )
		return 0;
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Upgrade" , INT_TO_PTR( conn->handshake->upgrade_websocket ) ) )
		return 0;
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Connection" , INT_TO_PTR( conn->handshake->connection_upgrade ) ) )
		return 0;
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Sec-WebSocket-Key" , conn->handshake->websocket_key ) )
		return 0;
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Origin" , conn->origin ) )
		return 0;
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Sec-WebSocket-Protocol" , conn->protocols ) )
		return 0;
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Sec-WebSocket-Version" , conn->handshake->websocket_version ) )
		return 0;
	if( nopoll_conn_check_mime_header_repeated( conn , header , value , "Cookie" , conn->handshake->cookie ) )
		return 0;

	/* set the value if required */
	if( strcasecmp( header , "Host" ) == 0 )
		conn->host_name = value;
	else if( strcasecmp( header , "Sec-Websocket-Key" ) == 0 )
		conn->handshake->websocket_key = value;
	else if( strcasecmp( header , "Origin" ) == 0 )
		conn->origin = value;
	else if( strcasecmp( header , "Sec-Websocket-Protocol" ) == 0 )
		conn->protocols = value;
	else if( strcasecmp( header , "Sec-Websocket-Version" ) == 0 )
		conn->handshake->websocket_version = value;
	else if( strcasecmp( header , "Upgrade" ) == 0 )
	{
		conn->handshake->upgrade_websocket = 1;
		nopoll_free( value );
	}
	else if( strcasecmp( header , "Connection" ) == 0 )
	{
		conn->handshake->connection_upgrade = 1;
		nopoll_free( value );
	}
	else if( strcasecmp( header , "Cookie" ) == 0 )
	{
		/* record cookie so it can be used by the application level */
		conn->handshake->cookie = value;
	}
	else
	{
		/* release value, no body claimed it */
		nopoll_free( value );
	} /* end if */

	  /* release the header */
	nopoll_free( header );

	return 1; /* continue reading lines */
}
//完成握手
void les_ssl_complete_handshake( LES_SSL_Conn* pConn )
{
	if( pConn == NULL || pConn->bHandshake_ok )
		return;
	char strBuffer[1024] = { "" };
	int nBuffer_size = 0;
	LES_SSL_Context* pCtx = pConn->pCtx;

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Checking to complete conn-id=%d WebSocket handshake, role %d" , pConn->nId , pConn->nRole );

	/* ensure handshake object is created */
	if( pConn->pHandshake == NULL )
		pConn->pHandshake = calloc_new( LES_SSL_Handshake , 1 );

	/* get lines and complete the handshake data */
	while( true )
	{
		/* clear buffer for debugging functions */
		strBuffer[0] = 0;
		/* get next line to process */
		nBuffer_size = les_ssl_conn_readline( pConn , strBuffer , 1024 );
		if( nBuffer_size == 0 || nBuffer_size == -1 )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "Unexpected connection close during handshake..closing connection" );
			les_ssl_conn_shutdown( pConn );
			return;
		} 

		  /* no data at this moment, return to avoid consuming data */
		if( nBuffer_size == -2 )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "No more data available on connection id %d" , pConn->nId );
			return;
		}

		/* drop a debug line */
		les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Bytes read %d from connection id %d: %s" , nBuffer_size , pConn->nId , strBuffer );

		/* check if we have received the end of the
		websocket client handshake */
		if( nBuffer_size == 2 && les_ssl_ncmp( strBuffer , "\r\n" , 2 ) )
		{
			les_ssl_handshake_check( pConn );
			return;
		}

		if( pConn->nRole == LES_SSL_ROLE_LISTENER )
		{
			/* call to complete listener handshake */
			if( les_ssl_complete_handshake_listener( pCtx , pConn , strBuffer , nBuffer_size ) == 1 )
				continue;
		}
		else if( pConn->nRole == LES_SSL_ROLE_CLIENT )
		{
			/* call to complete listener handshake */
			if( les_ssl_handshake_check_client( pCtx , pConn , strBuffer , nBuffer_size ) == 1 )
				continue;
		}
		else
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "Called to handle connection handshake on a connection with an unexpected role: %d, closing session" 
				, pConn->nRole );
			les_ssl_conn_shutdown( pConn );
			return;
		}
	} /* end while */

	return;
}