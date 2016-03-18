#include "../Header.h"

#define LOGGING_PYTHON_FILE "..//log//log.py"
#define LOGGING_FILE "..//log//test-openssl.log"
bool bLoggingSuc = false;
void startLogging( )
{
	char strCmd[MAX_PATH] = "";
	sprintf_s( strCmd , MAX_PATH , "python %s %s w %s" , LOGGING_PYTHON_FILE , LOGGING_FILE , "start!!!" );
	int nRet = system( strCmd );
	if( nRet == 0 )
		bLoggingSuc = true;
}
void WriteLogging( const char* strFile , long lLine , const char* strMsg )
{
	if( !bLoggingSuc )
		return;

	char strCmd[MAX_PATH] = "";
	if( strFile != NULL )
		sprintf_s( strCmd , MAX_PATH , "python %s %s a %s %ld %s" , LOGGING_PYTHON_FILE , LOGGING_FILE , strFile , lLine , strMsg );
	else
		sprintf_s( strCmd , MAX_PATH , "python %s %s a %s" , LOGGING_PYTHON_FILE , LOGGING_FILE , strMsg );

	int nRet = system( strCmd );
	if( nRet == 0 )
		bLoggingSuc = true;
}
void les_ssl_print( int nLevel , const char* strFile , long lLine , const char* strMsg , ... )
{
	va_list args;
	char* strHeader = NULL;
	if( nLevel & LES_SSL_LOGGING_MSG )
		strHeader = "Msg";
	else if( nLevel & LES_SSL_LOGGING_ERR )
		strHeader = "Err";
	else if( nLevel & LES_SSL_LOGGING_DEBUG )
		strHeader = "Debug";
	if( ( nLevel & LES_SSL_LOGGING_MSG ) || ( nLevel & LES_SSL_LOGGING_ERR ) )
	{
		char strTmp[MAX_PATH] = "";
		/* print the message */
		va_start( args , strMsg );
		vsprintf_s( strTmp , MAX_PATH , strMsg , args );
		va_end( args );

		strMsg = strTmp;
		printf( strMsg );
		printf( "\n" );
		
		char strTmpLog[MAX_PATH] = "";
		sprintf_s( strTmpLog , MAX_PATH , "\"%s: %s\"" , strHeader , strMsg );
		strMsg = strTmpLog;
		
	}

	if( LES_SSL_LOGGING_PRINT_DEBUG )
	{
		if( nLevel & LES_SSL_LOGGING_DEBUG )
			WriteLogging( strFile , lLine , strMsg );
	}
}