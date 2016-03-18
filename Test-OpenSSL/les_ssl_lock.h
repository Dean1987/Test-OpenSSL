#ifndef _LES_SSL_LOCK_H
#define _LES_SSL_LOCK_H
voidPtr les_ssl_mutex_create( void );
void les_ssl_mutex_destroy( voidPtr mutex );
void les_ssl_mutex_lock( voidPtr mutex );
void les_ssl_mutex_unlock( voidPtr mutex );
#endif
