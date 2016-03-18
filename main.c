#include "Header.h"
#include "Test-OpenSSL/les_ssl_struct.h"

void InitTcp( )
{
	WSADATA		wsa;
	memset( &wsa , 0 , sizeof( WSADATA ) );
	int			ierr = 0;
	ierr = WSAStartup( MAKEWORD( 2 , 0 ) , &wsa );
	if( ierr != 0 )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "WSAStartup Fail!" );
	}
}

int main( )
{
	startLogging( );
	InitTcp( );
	if( test_01_base64( ) )
	{
		les_ssl_print( LES_SSL_LOGGING_MSG | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE 
			, "Test 01-bas64: Library bas64 support [   OK   ]" );
	}
	else
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE ,
			"Test 01-bas64: Library bas64 support [ FAILED ]" );
		return -1;
	}
	test_01_masking( );
	test_01( );
    return 0;
}
