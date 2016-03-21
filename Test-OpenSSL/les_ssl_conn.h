#ifndef _LES_SSL_CONN_H
#define _LES_SSL_CONN_H
#include "../Header.h"

LES_SSL_Conn* les_ssl_conn_new( LES_SSL_Context* pCtx , const char* strHost_ip , const char* strHost_port
	, const char* strHost_name , const char* strGet_url , const char* strProtocols , const char* strOrigin
	, LES_SSL_ConnOpts* pOptions , bool bEnable_tls );
void les_ssl_conn_shutdown( LES_SSL_Conn * pConn );
bool les_ssl_conn_is_ok( LES_SSL_Conn* pConn );
bool les_ssl_conn_is_ready( LES_SSL_Conn* pConn );
SOCKET les_ssl_conn_socket( LES_SSL_Conn* pConn );
int les_ssl_conn_ref_count( LES_SSL_Conn* pConn );
void les_ssl_conn_mask_content( LES_SSL_Context* ctx , char* payload , int payload_size , char* mask , int desp );
size_t les_ssl_conn_readline( LES_SSL_Conn* pConn , char* strBuffer , int nMaxlen );
bool les_ssl_conn_get_http_url( LES_SSL_Conn* pConn , const char* strBuffer 
	, size_t nBuffer_size , const char* strMethod , char** strUrl );
bool les_ssl_conn_get_mime_header( LES_SSL_Context* pCtx , LES_SSL_Conn* pConn , const char* strBuffer , size_t nBuffer_size
	, char** strHeader , char** strValue );
bool les_ssl_conn_check_mime_header_repeated( LES_SSL_Conn* pConn , char* strHeader , char* strValue ,
	const char* strRef_header , voidPtr pCheck );
int les_ssl_conn_complete_pending_write( LES_SSL_Conn* pConn );
int les_ssl_conn_send_frame( LES_SSL_Conn * strConn , bool bFin , bool bMasked ,
	LES_SSL_OpCode nOp_code , long lLength , voidPtr strContent , long lSleep_in_header );
void les_ssl_conn_close( LES_SSL_Conn* pConn , int nStatus , const char* strReason , int nReason_size );
bool les_ssl_conn_ref( LES_SSL_Conn* pConn );
void les_ssl_conn_unref( LES_SSL_Conn* pConn );
#endif