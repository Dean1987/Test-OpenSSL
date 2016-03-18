#include "../Header.h"
#include "les_ssl_struct.h"
#include "les_ssl_context.h"
#include "les_ssl_conn.h"

bool test_01_base64( )
{
	char buffer[1024];
	size_t  size = 1024;
	int  iterator = 0;

	/* call to produce base 64 (we do a loop to ensure we don't
	* leak through openssl (220) bytes */
	while( iterator < 10 )
	{
		size = 1024;
		if( !base64_encode( "This is a test" , 14 , buffer , &size ) )
		{
			printf( "ERROR: failed to encode this is a test..\n" );
			return false;
		} /* end if */

		  /* check result */
		if( strcmp( buffer , "VGhpcyBpcyBhIHRlc3Q=" ) != 0 )
		{
			printf( "ERROR: expected to find encoded base64 string %s but found %s..\n" ,
				"VGhpcyBpcyBhIHRlc3Q=" , buffer );
			return false;
		}

		iterator++;
	}

	/* now decode content */
	iterator = 0;
	while( iterator < 10 )
	{
		int nSize = 1024;
		if( !base64_decode( "VGhpcyBpcyBhIHRlc3Q=" , 20 , buffer , &nSize ) )
		{
			printf( "ERROR: failed to decode base64 content..\n" );
		}

		/* check result */
		if( strcmp( buffer , "This is a test" ) != 0 )
		{
			printf( "ERROR: expected to find encoded base64 string %s but found %s..\n" ,
				"This is a test" , buffer );
			return false;
		} /* end if */

		iterator++;
	}

	return true;
}

bool test_01_masking( )
{
	char mask[4];
	int mask_value;
	char buffer[1024];
	LES_SSL_Context* ctx;

	/* clear buffer */
	memset( buffer , 0 , 1024 );

	/* create context */
	ctx = les_ssl_context_new( );

	mask_value = rand( );

	printf( "Test-01 masking: using masking value %d\n" , mask_value );
	set_32bit( mask_value , mask );

	memcpy( buffer , "This is a test value" , 20 );
	conn_mask_content( ctx , buffer , 20 , mask , 0 );

	if( les_ssl_ncmp( buffer , "This is a test value" , 20 ) )
	{
		printf( "ERROR: expected to find different values after masking but found the same..\n" );
		return false;
	}

	///* revert changes */
	conn_mask_content( ctx , buffer , 20 , mask , 0 );

	if( !les_ssl_ncmp( buffer , "This is a test value" , 20 ) )
	{
		printf( "ERROR: expected to find SAME values after masking but found the same..\n" );
		return false;
	} /* end if */

	  /* now check transfering these values to the mask */
	if( get_32bit( mask ) != mask_value )
	{
		printf( "ERROR: found failure while reading the mask from from buffer..\n" );
		return false;
	}
	printf( "Test 01 masking: found mask in the buffer %d == %d\n" ,
		get_32bit( mask ) , mask_value );

	les_ssl_ctx_unref( ctx );
	return true;
}
bool test_01( )
{
	LES_SSL_Context* ctx = NULL;
	LES_SSL_Conn* conn = NULL;

	/* create context */
	ctx = les_ssl_context_new( );

	/* check connections registered */
	if( les_ssl_ctx_conns( ctx ) != 0 )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "expected to find 0 registered connections but found: %d" , les_ssl_ctx_conns( ctx ) );
		return false;
	}

	les_ssl_ctx_unref( ctx );

	/* reinit again */
	ctx = les_ssl_context_new( );

	///* call to create a connection */
	conn = les_ssl_conn_new( ctx , "localhost" , "1234" , NULL , NULL , NULL , NULL );
	if( !les_ssl_conn_is_ok( conn ) )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "ERROR: Expected to find proper client connection status , but found error( conn = %p "
			", conn->session = %d , NOPOLL_INVALID_SOCKET = %d ).." , conn , ( int ) les_ssl_conn_socket( conn ) , ( int ) INVALID_SOCKET );
		return false;
	}

	///* check connections registered */
	if( les_ssl_ctx_conns( ctx ) != 1 )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "ERROR: expected to find 1 registered connections but found: %d\n" , les_ssl_ctx_conns( ctx ) );
		return false;
	} 

	//  /* ensure connection status is ok */
	if( !les_ssl_conn_is_ok( conn ) )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "ERROR (3): expected to find proper connection status, but found failure.. (conn=%p, conn->session=%d, NOPOLL_INVALID_SOCKET=%d)..\n" ,
			conn , ( int ) les_ssl_conn_socket( conn ) , ( int ) INVALID_SOCKET );
		return false;
	}

	les_ssl_print( LES_SSL_LOGGING_MSG | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Test 01: reference counting for the connection: %d\n" , les_ssl_conn_ref_count( conn ) );

	///* check if the connection already finished its connection
	//handshake */
	while( !les_ssl_conn_is_ready( conn ) )
	{
		if( !les_ssl_conn_is_ok( conn ) )
		{
			les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
				, "ERROR (4.1 jkd412): expected to find proper connection handshake finished, but found connection is broken: session=%d, errno=%d : %s..\n" ,
				( int ) les_ssl_conn_socket( conn ) , errno , strerror( errno ) );
			return false;
		} 

		/* wait a bit 10ms */
		Sleep( 10 );
	} 

	//  /* finish connection */
	les_ssl_conn_close( conn );

	///* finish */
	les_ssl_ctx_unref( ctx );

	return true;
}