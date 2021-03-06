﻿#include "les_ssl_struct.h"
#include "les_ssl_context.h"
#include "les_ssl_conn.h"
#include "les_ssl_conn_opts.h"
#include "les_ssl_handshake.h"
#include "les_ssl_string.h"
#include "les_ssl_msg.h"

bool g_bNonce_init = false;

//设置非延时
bool conn_set_sock_tcp_nodelay( SOCKET sSocket , bool bEnable )
{
	int nResult = 0;

	nResult = setsockopt( sSocket , IPPROTO_TCP , TCP_NODELAY , ( char  * ) &bEnable , sizeof( bool ) );

	if( nResult == INVALID_SOCKET )
	{
		return false;
	}

	return true;
}

bool conn_set_sock_block( SOCKET sSocket , bool bEnable )
{
	u_long lArg = bEnable;
	if( ioctlsocket( sSocket , FIONBIO , &lArg ) != 0 )
	{
		return false;
	}

	return true;
}

bool get_nonce( char* strBuffer , int nNonce_size )
{
	int nRandom_value = 0;
	int nIterator = 0;

	if( strBuffer == NULL || nNonce_size <= 0 )
		return false;
	if( !g_bNonce_init )
	{
		srand( ( UINT ) time( NULL ) );
		g_bNonce_init = true;
	}

	  /* now get the value from random */
	nIterator = 0;
	while( nIterator < nNonce_size )
	{
		nRandom_value = rand( );

		/* copy into the buffer */
		memcpy( strBuffer + nIterator , &nRandom_value , sizeof( nRandom_value ) );
		nIterator += sizeof( nRandom_value );
	} /* end while */

	return true;
}

char* conn_get_client_init( LES_SSL_Conn* pConn , LES_SSL_ConnOpts* pOpts )
{
	/* build sec-websocket-key */
	char strKey[50] = { "" };
	size_t nKey_size = 50;
	char strNonce[17] = { "" };

	/* get the nonce */
	if( !get_nonce( strNonce , 16 ) )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Failed to get nonce, unable to produce Sec-WebSocket-Key." );
		return NULL;
	} /* end if */

	  /* now base 64 */
	if( !base64_encode( strNonce , 16 , strKey , &nKey_size ) )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Unable to base 64 encode characters for Sec-WebSocket-Key" );
		return NULL;
	}

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
		, "Created Sec-WebSocket-Key nonce: %s" , strKey );

	/* create accept and store */
	pConn->pHandshake = calloc_new( LES_SSL_Handshake , 1 );
	pConn->pHandshake->strExpected_accept = _strdup( strKey );

	/* send initial handshake                                                                                                                        |cookie |prot  | */
	return les_ssl_string_printfv( "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nOrigin: %s\r\n%s%s%s%s%s%s%s%sSec-WebSocket-Version: %d\r\n\r\n" ,
		pConn->strGet_url , pConn->strHost_name ,
		/* sec-websocket-key */
		strKey ,
		/* Origin */
		pConn->strOrigin ,
		/* Cookie */
		( pOpts && pOpts->strCookie ) ? "Cookie" : "" ,
		( pOpts && pOpts->strCookie ) ? ": " : "" ,
		( pOpts && pOpts->strCookie ) ? pOpts->strCookie : "" ,
		( pOpts && pOpts->strCookie ) ? "\r\n" : "" ,
		/* protocol part */
		pConn->strProtocols ? "Sec-WebSocket-Protocol" : "" ,
		pConn->strProtocols ? ": " : "" ,
		pConn->strProtocols ? pConn->strProtocols : "" ,
		pConn->strProtocols ? "\r\n" : "" ,
		pConn->pCtx->nProtocol_version );
}

int les_ssl_conn_default_receive( LES_SSL_Conn* pConn , char* strBuffer , size_t nBuffer_size )
{
	return recv( pConn->sSession , strBuffer , ( int ) nBuffer_size , 0 );
}

int les_ssl_conn_default_send( LES_SSL_Conn* pConn , char* strBuffer , size_t nBuffer_size )
{
	return send( pConn->sSession , strBuffer , ( int ) nBuffer_size , 0 );
}

SOCKET les_ssl_sock_connect( LES_SSL_Context* pCtx , const char * strHost ,	const char* strPort )
{
	struct hostent* pHostent = NULL;
	struct sockaddr_in sSaddr;
	SOCKET sSession = 0;

	/* resolve hosting name */
	pHostent = gethostbyname( strHost );
	if( pHostent == NULL )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "unable to resolve host name %s" , strHost );
		return -1;
	} 

	  /* create the socket and check if it */
	sSession = socket( AF_INET , SOCK_STREAM , 0 );
	if( sSession == INVALID_SOCKET )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "unable to create socket" );
		return -1;
	} 

	/* disable nagle */
	conn_set_sock_tcp_nodelay( sSession , true );

	/* prepare socket configuration to operate using TCP/IP
	* socket */
	memset( &sSaddr , 0 , sizeof( sSaddr ) );
	sSaddr.sin_addr.s_addr = ( ( struct in_addr * )( pHostent->h_addr ) )->s_addr;
	sSaddr.sin_family = AF_INET;
	sSaddr.sin_port = htons( ( u_short ) strtod( strPort , NULL ) );

	/* set non blocking status */
	conn_set_sock_block( sSession , false );

	/* do a tcp connect */
	if( connect( sSession , ( struct sockaddr * )&sSaddr , sizeof( sSaddr ) ) < 0 )
	{
		if( errno != WSAEINPROGRESS && errno != WSAEWOULDBLOCK && errno != WSAENOTCONN )
		{
			shutdown( sSession , SD_BOTH );
			closesocket( sSession );

			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "unable to connect to remote host %s:%s errno=%d" , strHost , strPort , errno );
			return -1;
		} 
	} 

	return sSession;
}

LES_SSL_Conn* les_ssl_conn_new( LES_SSL_Context* pCtx , const char* strHost_ip , const char* strHost_port
	, const char* strHost_name , const char* strGet_url , const char* strProtocols , const char* strOrigin 
	, LES_SSL_ConnOpts* pOptions , bool bEnable_tls )
{
	LES_SSL_Conn* pConn = NULL;
	SOCKET sSession = 0;
	char* strContent = NULL;
	size_t nSize = 0;
	int nSsl_error = 0;
	X509* sServer_cert = NULL;
	int nIterator = 0;
	long lRemaining_timeout = 0;

	if( pCtx == NULL || strHost_ip == NULL )
	{
		les_ssl_conn_opts_release( pOptions );
		return NULL;
	}

	if( strHost_port == NULL )
		strHost_port = "80";

	sSession = les_ssl_sock_connect( pCtx , strHost_ip , strHost_port );
	if( sSession == INVALID_SOCKET )
	{
		les_ssl_conn_opts_release( pOptions );
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Failed to connect to remote host %s:%s" , strHost_ip , strHost_port );
		return NULL;
	}

	/* create the connection */
	pConn = calloc_new( LES_SSL_Conn , 1 );
	if( pConn == NULL )
	{
		/* release connection options */
		les_ssl_conn_opts_release( pOptions );
		return NULL;
	}

	pConn->nRefs = 1;

	/* create mutex */
	pConn->pRef_mutex = les_ssl_mutex_create( );

	/* register connection into context */
	if( !les_ssl_ctx_register_conn( pCtx , pConn ) )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Failed to register connection into the context, unable to create connection" );
		free( pConn );
		/* release connection options */
		les_ssl_conn_opts_release( pOptions );

		return NULL;
	}

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Created noPoll conn-id=%d (ptr: %p, context: %p, socket: %d)" ,
		pConn->nId , pConn , pCtx , sSession );

	/* configure context */
	pConn->pCtx = pCtx;
	pConn->sSession = sSession;
	pConn->nRole = LES_SSL_ROLE_CLIENT;

	/* record host and port */
	pConn->strHost = _strdup( strHost_ip );
	pConn->strPort = _strdup( strHost_port );

	/* configure default handlers */
	pConn->pReceive = les_ssl_conn_default_receive;
	pConn->pSend = les_ssl_conn_default_send;

	/* build host name */
	if( strHost_name == NULL )
		pConn->strHost_name = _strdup( strHost_ip );
	else
		pConn->strHost_name = _strdup( strHost_name );

	/* build origin */
	if( strOrigin == NULL )
		pConn->strOrigin = les_ssl_string_printfv( "http://%s" , pConn->strHost_name );
	else
		pConn->strOrigin = _strdup( strOrigin );

	/* get url */
	if( strGet_url == NULL )
		pConn->strGet_url = _strdup( "/" );
	else
		pConn->strGet_url = _strdup( strGet_url );

	/* protocols */
	if( strProtocols != NULL )
		pConn->strProtocols = _strdup( strProtocols );


	/* get client init payload */
	strContent = conn_get_client_init( pConn , pOptions );

	if( strContent == NULL )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Failed to build client init message, unable to connect" );
		les_ssl_conn_shutdown( pConn );

		/* release connection options */
		les_ssl_conn_opts_release( pOptions );

		return NULL;
	}

	/* check for TLS support */
	//if( bEnable_tls )
	//{
	//	/* found TLS connection request, enable it */
	//	pConn->pSsl_ctx = __nopoll_conn_get_ssl_context( ctx , conn , options , nopoll_true );

	//	/* check for client side SSL configuration */
	//	if( !__nopoll_conn_set_ssl_client_options( ctx , conn , options ) )
	//	{
	//		nopoll_log( ctx , NOPOLL_LEVEL_CRITICAL , "Unable to configure additional SSL options, unable to continue" ,
	//			conn->ssl_ctx , conn->ssl );
	//		goto fail_ssl_connection;
	//	} /* end if */

	//	  /* create context and check for result */
	//	conn->ssl = SSL_new( conn->ssl_ctx );
	//	if( conn->ssl_ctx == NULL || conn->ssl == NULL )
	//	{
	//		nopoll_log( ctx , NOPOLL_LEVEL_CRITICAL , "Unable to create SSL context internal references are null (conn->ssl_ctx=%p, conn->ssl=%p)" ,
	//			conn->ssl_ctx , conn->ssl );
	//	fail_ssl_connection:

	//		nopoll_free( content );
	//		nopoll_conn_shutdown( conn );

	//		/* release connection options */
	//		__nopoll_conn_opts_release_if_needed( options );

	//		return conn;
	//	} /* end if */

	//	  /* set socket */
	//	SSL_set_fd( conn->ssl , conn->session );

	//	/* do the initial connect connect */
	//	nopoll_log( ctx , NOPOLL_LEVEL_DEBUG , "connecting to remote TLS site" );
	//	iterator = 0;
	//	while( SSL_connect( conn->ssl ) <= 0 )
	//	{

	//		/* get ssl error */
	//		ssl_error = SSL_get_error( conn->ssl , -1 );

	//		switch( ssl_error )
	//		{
	//			case SSL_ERROR_WANT_READ:
	//				nopoll_log( ctx , NOPOLL_LEVEL_WARNING , "still not prepared to continue because read wanted, conn-id=%d (%p, session: %d), errno=%d" ,
	//					conn->id , conn , conn->session , errno );
	//				break;
	//			case SSL_ERROR_WANT_WRITE:
	//				nopoll_log( ctx , NOPOLL_LEVEL_WARNING , "still not prepared to continue because write wanted, conn-id=%d (%p)" ,
	//					conn->id , conn );
	//				break;
	//			case SSL_ERROR_SYSCALL:
	//				nopoll_log( ctx , NOPOLL_LEVEL_CRITICAL , "syscall error while doing TLS handshake, ssl error (code:%d), conn-id: %d (%p), errno: %d, session: %d" ,
	//					ssl_error , conn->id , conn , errno , conn->session );
	//				nopoll_conn_log_ssl( conn );
	//				nopoll_conn_shutdown( conn );
	//				nopoll_free( content );

	//				/* release connection options */
	//				__nopoll_conn_opts_release_if_needed( options );

	//				return conn;
	//			default:
	//				nopoll_log( ctx , NOPOLL_LEVEL_CRITICAL , "there was an error with the TLS negotiation, ssl error (code:%d) : %s" ,
	//					ssl_error , ERR_error_string( ssl_error , NULL ) );
	//				nopoll_conn_log_ssl( conn );
	//				nopoll_conn_shutdown( conn );
	//				nopoll_free( content );

	//				/* release connection options */
	//				__nopoll_conn_opts_release_if_needed( options );

	//				return conn;
	//		} /* end switch */

	//		  /* try and limit max reconnect allowed */
	//		iterator++;

	//		if( iterator > 100 )
	//		{
	//			nopoll_log( ctx , NOPOLL_LEVEL_CRITICAL , "Max retry calls=%d to SSL_connect reached, shutting down connection id=%d, errno=%d" ,
	//				iterator , conn->id , errno );
	//			nopoll_free( content );

	//			/* release connection options */
	//			__nopoll_conn_opts_release_if_needed( options );

	//			return conn;
	//		} /* end if */

	//		  /* wait a bit before retry */
	//		nopoll_sleep( 10000 );

	//	} /* end while */

	//	nopoll_log( ctx , NOPOLL_LEVEL_DEBUG , "Client TLS handshake finished, configuring I/O handlers" );

	//	/* check remote certificate (if it is present) */
	//	server_cert = SSL_get_peer_certificate( conn->ssl );
	//	if( server_cert == NULL )
	//	{
	//		nopoll_log( ctx , NOPOLL_LEVEL_CRITICAL , "server side didn't set a certificate for this session, these are bad news" );

	//		/* release connection options */
	//		nopoll_free( content );
	//		__nopoll_conn_opts_release_if_needed( options );

	//		return conn;
	//	}
	//	X509_free( server_cert );

	//	/* call to check post ssl checks after SSL finalization */
	//	if( conn->ctx && conn->ctx->post_ssl_check )
	//	{
	//		if( !conn->ctx->post_ssl_check( conn->ctx , conn , conn->ssl_ctx , conn->ssl , conn->ctx->post_ssl_check_data ) )
	//		{
	//			/* TLS post check failed */
	//			nopoll_log( conn->ctx , NOPOLL_LEVEL_CRITICAL , "TLS/SSL post check function failed, dropping connection" );
	//			nopoll_conn_shutdown( conn );
	//			return NULL;
	//		} /* end if */
	//	} /* end if */

	//	  /* configure default handlers */
	//	conn->receive = nopoll_conn_tls_receive;
	//	conn->send = nopoll_conn_tls_send;

	//	nopoll_log( ctx , NOPOLL_LEVEL_DEBUG , "TLS I/O handlers configured" );
	//	conn->tls_on = nopoll_true;
	//}

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
		, "Sending websocket client init: %s" , strContent );
	nSize = strlen( strContent );

	/* call to send content */
	lRemaining_timeout = pCtx->lConn_connect_std_timeout;
	while( lRemaining_timeout > 0 )
	{
		if( nSize != pConn->pSend( pConn , strContent , nSize ) )
		{
			/* for some reason, under FreeBSD, a ENOTCONN is reported when they should be returning EINPROGRESS and/or EWOULDBLOCK */
			if( errno != WSAEINPROGRESS && errno != WSAEWOULDBLOCK && errno != WSAENOTCONN )
			{
				Sleep( 10 );
				lRemaining_timeout -= 10000;
				continue;
			}

			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "Failed to send websocket init message, error code was: %d (2), closing session" , errno );
			les_ssl_conn_shutdown( pConn );
		}

		break;
	}

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Web socket initial client handshake sent" );

	/* release content */
	free( strContent );

	/* release connection options */
	les_ssl_conn_opts_release( pOptions );

	/* return connection created */
	return pConn;
}

void les_ssl_conn_shutdown( LES_SSL_Conn * pConn )
{
	const char* strRole = NULL;

	if( pConn == NULL )
		return;
	if( pConn->nRole == LES_SSL_ROLE_LISTENER )
		strRole = "listener";
	else if( pConn->nRole == LES_SSL_ROLE_MAIN_LISTENER )
		strRole = "master-listener";
	else if( pConn->nRole == LES_SSL_ROLE_UNKNOWN )
		strRole = "unknown";
	else if( pConn->nRole == LES_SSL_ROLE_CLIENT )
		strRole = "client";
	else
		strRole = "unknown";

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "shutting down connection id=%d (session: %d, role: %d)" ,
		pConn->nId , pConn->sSession , pConn->nRole );

	/* call to on close handler if defined */
	if( pConn->sSession != INVALID_SOCKET && pConn->oOn_close )
		pConn->oOn_close( pConn->pCtx , pConn , pConn->pOn_close_data );

	/* shutdown connection here */
	if( pConn->sSession != INVALID_SOCKET )
	{
		shutdown( pConn->sSession , SD_BOTH );
		closesocket( pConn->sSession );
	}
	pConn->sSession = INVALID_SOCKET;

	return;
}

void les_ssl_conn_mask_content( LES_SSL_Context* ctx , char* payload , int payload_size , char* mask , int desp )
{
	int iter = 0;
	int mask_index = 0;

	while( iter < payload_size )
	{
		/* rotate mask and apply it */
		mask_index = ( iter + desp ) % 4;
		payload[iter] ^= mask[mask_index];
		iter++;
	} /* end while */

	return;
}

bool les_ssl_conn_is_ok( LES_SSL_Conn* pConn )
{
	if( pConn == NULL )
		return false;
	return pConn->sSession != INVALID_SOCKET;
}

SOCKET les_ssl_conn_socket( LES_SSL_Conn* pConn )
{
	if( pConn == NULL )
		return -1;
	return pConn->sSession;
}

int les_ssl_conn_ref_count( LES_SSL_Conn* pConn )
{
	if( pConn == NULL )
		return -1;
	return pConn->nRefs;
}

bool les_ssl_conn_is_ready( LES_SSL_Conn* pConn )
{
	if( pConn == NULL )
		return false;
	if( pConn->sSession == INVALID_SOCKET )
		return false;
	if( !pConn->bHandshake_ok )
	{
		/* acquire here handshake mutex */
		les_ssl_mutex_lock( pConn->pRef_mutex );

		/* complete handshake */
		les_ssl_complete_handshake( pConn );

		/* release here handshake mutex */
		les_ssl_mutex_unlock( pConn->pRef_mutex );
	}
	return pConn->bHandshake_ok;
}

size_t les_ssl_conn_readline( LES_SSL_Conn* pConn , char* strBuffer , int nMaxlen )
{
	int nRc = 0;
	size_t nDesp = 0;
	char* strPtr = NULL;

	/* clear the buffer received */
	/* memset (buffer, 0, maxlen * sizeof (char ));  */

	/* check for pending line read */
	nDesp = 0;
	if( pConn->strPending_line != NULL )
	{
		/* get size and check exceeded values */
		nDesp = strlen( pConn->strPending_line );
		if( nDesp >= nMaxlen )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "found fragmented frame line header but allowed size was exceeded (desp:%d >= maxlen:%d)"
				, nDesp , nMaxlen );
			les_ssl_conn_shutdown( pConn );
			return -1;
		} 

		  /* now store content into the buffer */
		memcpy( strBuffer , pConn->strPending_line , nDesp );

		/* clear from the conn the line */
		free( pConn->strPending_line );
		pConn->strPending_line = NULL;
	}

	/* read current next line */
	strPtr = ( strBuffer + nDesp );
	int n = 0;
	for( n = 1; n < ( nMaxlen - nDesp ); n++ )
	{
		char c = '\0';
		int nRc = 0;
		if( ( nRc = pConn->pReceive( pConn , &c , 1 ) ) == 1 )
		{
			*strPtr++ = c;
			if( c == '\x0A' )
				break;
		}
		else if( nRc == 0 )
		{
			if( n == 1 )
				return 0;
			else
				break;
		}
		else
		{
			if( errno == WSAEINTR )
			{
				n--;
				continue;
			}
			if( ( errno == WSAEWOULDBLOCK )  || ( nRc == -2 ) )
			{
				if( n > 0 )
				{
					/* store content read until now */
					if( ( n + nDesp - 1 ) > 0 )
					{
						strBuffer[n + nDesp - 1] = 0;
						pConn->strPending_line = _strdup( strBuffer );
					}
				}
				return -2;
			}

			if( les_ssl_conn_is_ok( pConn ) && errno == 0 && nRc == 0 )
			{
				les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
					, "unable to read line, but errno is 0, and connection is ok, return to keep on trying.." );
				return -2;
			}

			/* if the conn is closed, just return
			* without logging a message */
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
				, "unable to read line, error code errno: %d, rc: %d (%s)" ,
				errno , nRc , strerror( errno ) );
			return ( -1 );
		}
	}
	*strPtr = 0;
	return ( n + nDesp );
}
bool les_ssl_conn_get_http_url( LES_SSL_Conn* pConn , const char* strBuffer , size_t nBuffer_size , const char* strMethod , char** strUrl )
{
	int nIterator = 0;
	int nIterator2 = 0;

	/* check if we already received method */
	if( pConn->strGet_url )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Received GET method declartion when it was already received during handshake..closing session" );
		les_ssl_conn_shutdown( pConn );
		return false;
	} 

	  /* the get url must have a minimum size: GET / HTTP/1.1\r\n 16 (15 if only \n) */
	if( nBuffer_size < 15 )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Received uncomplete GET method during handshake, closing session" );
		les_ssl_conn_shutdown( pConn );
		return false;
	} 

	/* skip white spaces */
	nIterator = 4;
	while( nIterator <  nBuffer_size && strBuffer[nIterator] == ' ' )
		nIterator++;
	if( nBuffer_size == nIterator )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Received a %s method without an starting request url, closing session" , strMethod );
		les_ssl_conn_shutdown( pConn );
		return false;
	} 

	/* now check url format */
	if( strBuffer[nIterator] != '/' )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Received a %s method with a request url that do not start with /, closing session" , strMethod );
		les_ssl_conn_shutdown( pConn );
		return false;
	}

	/* ok now find the rest of the url content util the next white space */
	nIterator2 = ( nIterator + 1 );
	while( nIterator2 <  nBuffer_size && strBuffer[nIterator2] != ' ' )
		nIterator2++;
	if( nBuffer_size == nIterator2 )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Received a %s method with an uncomplate request url, closing session" , strMethod );
		les_ssl_conn_shutdown( pConn );
		return false;
	} 

	( *strUrl ) = calloc_new( char , nIterator2 - nIterator + 1 );
	memcpy( *strUrl , strBuffer + nIterator , nIterator2 - nIterator );
	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE , "Found url method: '%s'" , *strUrl );

	/* now check final HTTP header */
	nIterator = nIterator2 + 1;
	while( nIterator <  nBuffer_size && strBuffer[nIterator] == ' ' )
		nIterator++;
	if( nBuffer_size == nIterator )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Received a %s method with an uncomplate request url, closing session" , strMethod );
		les_ssl_conn_shutdown( pConn );
		return false;
	} 

	  /* now check trailing content */
	return les_ssl_cmp( strBuffer + nIterator , "HTTP/1.1\r\n" ) == 0
		|| les_ssl_cmp( strBuffer + nIterator , "HTTP/1.1\n" );
}

bool les_ssl_conn_get_mime_header( LES_SSL_Context* pCtx , LES_SSL_Conn* pConn , const char* strBuffer , size_t nBuffer_size 
	, char** strHeader , char** strValue )
{
	int nIterator = 0;
	int nIterator2 = 0;

	/* ok, find the first : */
	while( nIterator < nBuffer_size && strBuffer[nIterator] && strBuffer[nIterator] != ':' )
		nIterator++;
	if( strBuffer[nIterator] != ':' )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Expected to find mime header separator : but it wasn't found (buffer_size=%d, iterator=%d, content: [%s].."
			, nBuffer_size , nIterator , strBuffer );
		return false;
	}

	/* copy the header value */
	( *strHeader ) = calloc_new( char , nIterator + 1 );
	memcpy( *strHeader , strBuffer , nIterator );

	/* now get the mime header value */
	nIterator2 = nIterator + 1;
	while( nIterator2 < nBuffer_size && strBuffer[nIterator2] && strBuffer[nIterator2] != '\n' )
		nIterator2++;
	if( strBuffer[nIterator2] != '\n' )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Expected to find mime header value end (13) but it wasn't found (iterator=%d, iterator2=%d,"
			"for header: [%s], found value: [%d]), inside content: [%s].."
			, nIterator , nIterator2 , ( *strHeader ) , ( int ) strBuffer[nIterator2] , strBuffer );
		free( *strHeader );
		( *strHeader ) = NULL;
		( *strValue ) = NULL;
		return false;
	}

	/* copy the value */
	( *strValue ) = calloc_new( char , ( nIterator2 - nIterator ) + 1 );
	memcpy( *strValue , strBuffer + nIterator + 1 , nIterator2 - nIterator );

	/* trim content */
	les_ssl_string_trim( *strValue , NULL );
	les_ssl_string_trim( *strHeader , NULL );

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
		, "Found MIME header: '%s' -> '%s'" , *strHeader , *strValue );
	return true;
}

bool les_ssl_conn_check_mime_header_repeated( LES_SSL_Conn* pConn , char* strHeader , char* strValue ,
	const char* strRef_header ,	voidPtr pCheck )
{
	if( _stricmp( strRef_header , strHeader ) == 0 )
	{
		if( pCheck )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "Provided header %s twice, closing connection" , strHeader );
			free( strHeader );
			free( strValue );
			les_ssl_conn_shutdown( pConn );
			return true;
		} 
	} 
	return false;
}
void les_ssl_conn_close( LES_SSL_Conn* pConn , int nStatus , const char* strReason , int nReason_size )
{
	int nRefs = 0;
	char* strContent = NULL;

	/* check input data */
	if( pConn == NULL )
		return;

	if( pConn->sSession != INVALID_SOCKET )
	{
		les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "requested proper connection close id=%d (session %d)" , pConn->nId , pConn->sSession );

		/* build reason indication */
		strContent = NULL;
		if( strReason && nReason_size > 0 )
		{
			/* send content */
			strContent = calloc_new( char , nReason_size + 3 );
			if( strContent )
			{
				set_16bit( nStatus , strContent );
				memcpy( strContent + 2 , strReason , nReason_size );
			}
		}

		/* send close without reason */
		les_ssl_conn_send_frame( pConn , true /* has_fin */ ,
			/* masked */
			pConn->nRole == LES_SSL_ROLE_CLIENT , LES_SSL_CLOSE_FRAME ,
			/* content size and content */
			nReason_size > 0 ? nReason_size + 2 : 0 , strContent ,
			/* sleep in header */
			0 );

		/* release content (if defined) */
		free( strContent );

		/* call to shutdown connection */
		les_ssl_conn_shutdown( pConn );
	} 

	  /* unregister connection from context */
	nRefs = les_ssl_conn_ref_count( pConn );
	les_ssl_ctx_unregister_conn( pConn->pCtx , pConn );

	/* avoid calling next unref in the case not enough references
	* are found */
	if( nRefs <= 1 )
		return;

	/* call to unref connection */
	les_ssl_conn_unref( pConn );

	return;
}

int les_ssl_conn_send_frame( LES_SSL_Conn * pConn , bool bFin , bool bMasked ,
	LES_SSL_OpCode nOp_code , long lLength , voidPtr strContent , long lSleep_in_header )

{
	char strHeader[14] = { "" };
	int nHeader_size = 0;
	char* strSsend_buffer = NULL;
	int nBytes_written = 0;
	char strMask[4] = { "" };
	unsigned int nMask_value = 0;
	int nDesp = 0;
	int nTries = 0;

	/* check for pending send operation */
	if( les_ssl_conn_complete_pending_write( pConn ) != 0 )
		return -1;

	/* clear header */
	memset( strHeader , 0 , 14 );

	/* set header codes */
	if( bFin )
		set_bit( strHeader , 7 );

	if( bMasked )
	{
		set_bit( strHeader + 1 , 7 );

		/* define a random mask */
		nMask_value = ( unsigned int ) rand( );

		memset( strMask , 0 , 4 );
		set_32bit( nMask_value , strMask );
	} 

	if( nOp_code )
	{
		/* set initial 4 bits */
		strHeader[0] |= nOp_code & 0x0f;
	}

	/* set default header size */
	nHeader_size = 2;

	/* according to message length */
	if( lLength < 126 )
	{
		strHeader[1] |= lLength;
	}
	else if( lLength < 65535 )
	{
		/* set the next header length is at least 65535 */
		strHeader[1] |= 126;
		nHeader_size += 2;
		/* set length into the next bytes */
		set_16bit( lLength , strHeader + 2 );

	}
#if defined _WIN64
	else if( lLength < 9223372036854775807 )
	{
		/* not supported yet */
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Unable to send the requested message, this requested is bigger "
			"than the value that can be supported by this platform (it should be < 65k)" );
		return -1;
	}
#endif
	else
	{
		les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Unable to send the requested message, this requested is bigger "
			"than the value that can be supported by this platform (it should be < 65k)" );
		return -1;
	}

	/* place mask */
	if( bMasked )
	{
		set_32bit( nMask_value , strHeader + nHeader_size );
		nHeader_size += 4;
	} 

	  /* allocate enough memory to send content */
	strSsend_buffer = calloc_new( char , lLength + nHeader_size + 2 );
	if( strSsend_buffer == NULL )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Unable to allocate memory to implement send operation" );
		return -1;
	} 

	  /* copy content to be sent */
	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Copying into the buffer %d bytes of header (total memory allocated: %d)" ,
		nHeader_size , ( int ) lLength + nHeader_size + 1 );
	memcpy( strSsend_buffer , strHeader , nHeader_size );
	if( lLength > 0 )
	{
		memcpy( strSsend_buffer + nHeader_size , strContent , lLength );

		/* mask content before sending if requested */
		if( bMasked )
			les_ssl_conn_mask_content( pConn->pCtx
				, strSsend_buffer + nHeader_size , lLength , strMask , 0 );
	}


	/* send content */
	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Mask used for this delivery: %d (about to send %d bytes)" ,
		get_32bit( strSsend_buffer + nHeader_size - 2 ) , ( int ) lLength + nHeader_size );
	/* clear errno status before writting */
	nDesp = 0;
	nTries = 0;
	while( true )
	{
		/* try to write bytes */
		if( lSleep_in_header == 0 )
		{
			nBytes_written = pConn->pSend( pConn , strSsend_buffer + nDesp , lLength + nHeader_size - nDesp );
		}
		else
		{
			les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
				, "Found sleep in header indication, sending header: %d bytes (waiting %ld)" , nHeader_size , lSleep_in_header );
			nBytes_written = pConn->pSend( pConn , strSsend_buffer , nHeader_size );
			if( nBytes_written == nHeader_size )
			{
				/* sleep after header ... */
				Sleep( lSleep_in_header / 1000 );

				/* now send the rest of the content (without the header) */
				nBytes_written = pConn->pSend( pConn , strSsend_buffer + nHeader_size , lLength );
				les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
					, "Rest of content written %d (header size: %d, length: %d)" ,
					nBytes_written , nHeader_size , lLength );
				nBytes_written = lLength + nHeader_size;
				les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
					, "final bytes_written %d" , nBytes_written );
			}
			else
			{
				les_ssl_print( LES_SSL_LOGGING_ERR| LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
					, "Requested to write %d bytes for the header but %d were written" ,
					nHeader_size , nBytes_written );
				return -1;
			} 
		} 

		if( ( nBytes_written + nDesp ) != ( lLength + nHeader_size ) )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
				, "Requested to write %d bytes but found %d written "
				"(masked? %d, mask: %u, header size: %d, length: %d), errno = %d : %s" ,
				( int ) lLength + nHeader_size - nDesp , nBytes_written , bMasked 
				, nMask_value , nHeader_size , ( int ) lLength , errno , strerror( errno ) );
		}
		else
		{
			/* accomulate bytes written to continue */
			if( nBytes_written > 0 )
				nDesp += nBytes_written;

			les_ssl_print(  LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
				, "Bytes written to the wire %d (masked? %d, mask: %u, header size: %d, length: %d)" ,
				nBytes_written , bMasked , nMask_value , nHeader_size , ( int ) lLength );
			break;
		} 

		  /* accomulate bytes written to continue */
		if( nBytes_written > 0 )
			nDesp += nBytes_written;

		/* increase tries */
		nTries++;

		if( ( errno != 0 ) || nTries > 50 )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
				, "Found errno=%d (%s) value while trying to bytes to the WebSocket conn-id=%d or max tries reached=%d" ,
				errno , strerror( errno ) , pConn->nId , nTries );
			break;
		} 

		/* wait a bit */
		Sleep( 10 );

	} /* end while */

	  /* record pending write bytes */
	pConn->nPending_write_bytes = lLength + nHeader_size - nDesp;

	/* check pending bytes for the next operation */
	if( pConn->nPending_write_bytes > 0 )
	{
		pConn->strPending_write = calloc_new( char , pConn->nPending_write_bytes );
		memcpy( pConn->strPending_write , strSsend_buffer + lLength + nHeader_size - pConn->nPending_write_bytes
			, pConn->nPending_write_bytes );

		les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Stored %d bytes starting from %d out of %d bytes (header size: %d)" ,
			pConn->nPending_write_bytes , lLength + nHeader_size - pConn->nPending_write_bytes 
			, lLength + nHeader_size , nHeader_size );
	} 


	/* release memory */
	free( strSsend_buffer );

	/* report at least what was written */
	if( nDesp - nHeader_size > 0 )
		return nDesp - nHeader_size;

	/* report last operation */
	return nBytes_written;
}

int les_ssl_conn_complete_pending_write( LES_SSL_Conn* pConn )
{
	int nBytes_written = 0;
	char* strReference = NULL;
	int nPending_bytes = 0;

	if( pConn == NULL || pConn->strPending_write == NULL )
		return 0;

	/* simple implementation */
	nBytes_written = pConn->pSend( pConn , pConn->strPending_write , pConn->nPending_write_bytes );
	if( nBytes_written == pConn->nPending_write_bytes )
	{
		les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Completed pending write operation with bytes=%d" , nBytes_written );
		free( pConn->strPending_write );
		pConn->strPending_write = NULL;
		return nBytes_written;
	}

	if( nBytes_written > 0 )
	{
		/* bytes written but not everything */
		nPending_bytes = pConn->nPending_write_bytes - nBytes_written;
		strReference = calloc_new( char , nPending_bytes );
		memcpy( strReference , pConn->strPending_write + nBytes_written , nPending_bytes );
		free( pConn->strPending_write );
		pConn->strPending_write = strReference;
		return nBytes_written;
	}

	les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Found complete write operation didn't finish well, result=%d, errno=%d, conn-id=%d" ,
		nBytes_written , errno , pConn->nId );
	return nBytes_written;
}

void les_ssl_conn_unref( LES_SSL_Conn* pConn )
{
	if( pConn == NULL )
		return;

	/* acquire here the mutex */
	les_ssl_mutex_lock( pConn->pRef_mutex );

	pConn->nRefs--;
	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Releasing connection id %d reference, current ref count status is: %d" ,
		pConn->nId , pConn->nRefs );
	if( pConn->nRefs != 0 )
	{
		/* release here the mutex */
		les_ssl_mutex_unlock( pConn->pRef_mutex );
		return;
	}
	/* release here the mutex */
	les_ssl_mutex_unlock( pConn->pRef_mutex );

	/* release message */
	if( pConn->pPending_msg )
		les_ssl_msg_unref( pConn->pPending_msg );

	/* release ctx */
	if( pConn->pCtx )
	{
		les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "Released context refs, now: %d" , pConn->pCtx->nRefs );
		les_ssl_ctx_unref( pConn->pCtx );
	} /* end if */
	pConn->pCtx = NULL;

	/* free all internal strings */
	free( pConn->strHost );
	free( pConn->strPort );
	free( pConn->strHost_name );
	free( pConn->strOrigin );
	free( pConn->strProtocols );
	free( pConn->strAccepted_protocol );
	free( pConn->strGet_url );

	/* close reason if any */
	free( pConn->strPeer_close_reason );

	/* release TLS certificates */
	free( pConn->strCertificate );
	free( pConn->strPrivate_key );
	free( pConn->strChain_certificate );

	/* release uncomplete message */
	if( pConn->pPrevious_msg )
		les_ssl_msg_unref( pConn->pPrevious_msg );

	if( pConn->pSsl )
		SSL_free( pConn->pSsl );
	if( pConn->pSsl_ctx )
		SSL_CTX_free( pConn->pSsl_ctx );

	/* release handshake internal data */
	if( pConn->pHandshake )
	{
		free( pConn->pHandshake->strWebsocket_key );
		free( pConn->pHandshake->strWebsocket_version );
		free( pConn->pHandshake->strWebsocket_accept );
		free( pConn->pHandshake->strExpected_accept );
		free( pConn->pHandshake->strCookie );
		free( pConn->pHandshake );
	}

	  /* release connection options if defined and reuse flag is not defined */
	if( pConn->pOpts && !pConn->pOpts->bReuse )
		les_ssl_conn_opts_free( pConn->pOpts );

	/* release pending write buffer */
	free( pConn->strPending_write );

	/* release mutex */
	les_ssl_mutex_destroy( pConn->pRef_mutex );

	free( pConn );

	return;
}

bool les_ssl_conn_ref( LES_SSL_Conn* pConn )
{
	if( pConn == NULL )
		return false;

	/* lock the mutex */
	les_ssl_mutex_lock( pConn->pRef_mutex );
	if( pConn->nRefs <= 0 )
	{
		/* unlock the mutex */
		les_ssl_mutex_unlock( pConn->pRef_mutex );
		return false;
	}

	pConn->nRefs++;

	/* release here the mutex */
	les_ssl_mutex_unlock( pConn->pRef_mutex );

	return true;
}
