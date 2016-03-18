#ifndef _LES_SSL_LOGGING_H
#define _LES_SSL_LOGGING_H

#ifdef _MSC_VER
#define LES_SSl_FILE __FILE__
#define LES_SSl_LINE __LINE__
#else
#define LES_SSl_FILE NULL
#define LES_SSl_LINE 0
#endif
#define LES_SSL_LOGGING_MSG 1
#define LES_SSL_LOGGING_ERR 2
#define LES_SSL_LOGGING_DEBUG 4

#define LES_SSL_LOGGING_PRINT_DEBUG 1
void les_ssl_print( int nLevel , const char* strFile , long lLine , const char* strMsg , ... );
void startLogging( );
void WriteLogging( const char* strFile , long lLine , const char* strMsg );
#endif
