#ifndef _LES_SSL_CONN_H
#define _LES_SSL_CONN_H
#include "../Header.h"

LES_SSL_Conn* les_ssl_conn_new( LES_SSL_Context* ctx , const char* host_ip , const char* host_port
	, const char* host_name , const char* get_url , const char* protocols , const char* origin );
void les_ssl_conn_shutdown( LES_SSL_Conn * pConn );
bool les_ssl_conn_is_ok( LES_SSL_Conn* pConn );
bool les_ssl_conn_is_ready( LES_SSL_Conn* pConn );
SOCKET les_ssl_conn_socket( LES_SSL_Conn* pConn );
int les_ssl_conn_ref_count( LES_SSL_Conn* pConn );
void conn_mask_content( LES_SSL_Context* ctx , char* payload , int payload_size , char* mask , int desp );
int les_ssl_conn_readline( LES_SSL_Conn* pConn , char* strBuffer , int nMaxlen );
bool les_ssl_conn_get_http_url( LES_SSL_Conn* pConn , const char* strBuffer , int nBuffer_size , const char* strMethod , char** strUrl );
#endif