#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Ras.h>
#pragma comment(lib,"ws2_32.lib")
#include <Windows.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
//#include <openssl/objects.h>
//#include <openssl/x509v3.h>
#include<openssl/buffer.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
#include "Test-OpenSSL/les_ssl_enum.h"
/***************************Predefine************************************/
typedef struct _LES_SSL_IoEngine LES_SSL_IoEngine;
typedef struct _LES_SSL_Context LES_SSL_Context;
typedef struct _LES_SSL_Conn LES_SSL_Conn;
typedef struct _LogHandler LogHandler;
typedef struct _SslContextCreator SslContextCreator;
typedef struct _SslPostCheck SslPostCheck;
typedef struct _LES_SSL_Msg LES_SSL_Msg;
typedef struct _LES_SSL_Handshake LES_SSL_Handshake;
typedef struct _LES_SSL_ConnOpts LES_SSL_ConnOpts;
/*********************************End*************************************/

typedef void* voidPtr;
typedef voidPtr( *IoMechCreate )  ( LES_SSL_Context* ctx );
typedef void( *IoMechDestroy )  ( LES_SSL_Context* ctx , voidPtr io_object );
typedef void( *IoMechClear )  ( LES_SSL_Context* ctx , voidPtr io_object );
typedef int( *IoMechWait )  ( LES_SSL_Context* ctx , voidPtr io_object );
typedef bool( *IoMechAddTo )  ( int ds , LES_SSL_Context* ctx , LES_SSL_Conn* conn , voidPtr io_object );
typedef bool( *IoMechIsSet )  ( LES_SSL_Context* ctx , int fds , voidPtr io_object );
typedef int( *LES_SSL_Read ) ( LES_SSL_Conn* conn ,char* buffer , int buffer_size );
typedef void( *OnMessageHandler ) ( LES_SSL_Context* ctx , LES_SSL_Conn* conn , LES_SSL_Msg* msg , voidPtr user_data );
typedef bool( *ActionHandler ) ( LES_SSL_Context* ctx , LES_SSL_Conn* conn , voidPtr user_data );
typedef void( *OnCloseHandler )    ( LES_SSL_Context* ctx , LES_SSL_Conn* conn , voidPtr user_data );
typedef voidPtr( *MutexCreate ) ( void );
typedef void( *MutexDestroy ) ( voidPtr mutex );
typedef void( *MutexLock ) ( voidPtr mutex );
typedef void( *MutexUnlock ) ( voidPtr mutex );
/****************************Test Function********************************/
bool test_01_base64( );
bool test_01_masking( );
bool test_01( );
/*********************************End*************************************/

/**********************************Macro**********************************/
#define calloc_new(type, count) (type *) calloc (count, sizeof (type))
/*********************************End*************************************/
bool les_ssl_ncmp( const char * string1 , const char * string2 , int bytes );
bool base64_encode( const char* strContent , int nLen ,	char* strOutput , size_t* sOutput );
bool base64_decode( const char* strContent , int nLen , char* strOutput , int* sOutput );

#include "Test-OpenSSL/les_ssl_lock.h"
#include "Test-OpenSSL/les_ssl_logging.h"
