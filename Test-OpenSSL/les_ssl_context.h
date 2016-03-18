#ifndef _LES_SSL_CONTEXT_H
#define _LES_SSL_CONTEXT_H
#include "../Header.h"
void set_32bit( int value , char * buffer );
int get_32bit( const char * buffer );

LES_SSL_Context* les_ssl_context_new( );
void les_ssl_ctx_unref( LES_SSL_Context* ctx );
int les_ssl_ctx_conns( LES_SSL_Context * ctx );

#endif