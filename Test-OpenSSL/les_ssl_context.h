#ifndef _LES_SSL_CONTEXT_H
#define _LES_SSL_CONTEXT_H

LES_SSL_Context* les_ssl_context_new( );
void les_ssl_ctx_unref( LES_SSL_Context* ctx );
int les_ssl_ctx_conns( LES_SSL_Context * ctx );
void les_ssl_ctx_unregister_conn( LES_SSL_Context* pCtx , LES_SSL_Conn* pConn );
#endif