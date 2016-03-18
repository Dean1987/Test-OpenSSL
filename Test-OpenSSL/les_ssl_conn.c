#include "les_ssl_struct.h"
#include "les_ssl_context.h"
#include "les_ssl_conn.h"
#include "les_ssl_conn_opts.h"
#include "les_ssl_handshake.h"

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
	, const char* host_name , const char* get_url , const char* protocols , const char* origin )
{
	LES_SSL_Conn* pConn = NULL;
	LES_SSL_ConnOpts* pOptions = NULL;
	SOCKET sSession = 0;
	char* strContent = NULL;
	int nSize = 0;
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
		, "shutting down connection id=%d (session: %d, role: %s)" ,
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

void conn_mask_content( LES_SSL_Context* ctx , char* payload , int payload_size , char* mask , int desp )
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

int les_ssl_conn_readline( LES_SSL_Conn* pConn , char* strBuffer , int nMaxlen )
{
	int nRc = 0;
	int nDesp = 0;
	char* strPtr = NULL;

	/* clear the buffer received */
	/* memset (buffer, 0, maxlen * sizeof (char ));  */

	/* check for pending line read */
	nDesp = 0;
	if( pConn->strPending_line );
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
						pConn->strPending_line = strdup( strBuffer );
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
bool les_ssl_conn_get_http_url( LES_SSL_Conn* pConn , const char* strBuffer , int nBuffer_size , const char* strMethod , char** strUrl )
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
	return strcmp( strBuffer + nIterator , "HTTP/1.1\r\n" ) == 0
		|| strcmp( strBuffer + nIterator , "HTTP/1.1\n" );
}