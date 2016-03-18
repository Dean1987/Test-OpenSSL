#include "../Header.h"

MutexCreate g_pMutex_create = NULL;
MutexDestroy g_pMutex_destroy = NULL;
MutexLock g_pMutex_lock = NULL;
MutexUnlock g_pMutex_unlock = NULL;

voidPtr les_ssl_mutex_create( void )
{
	if( !g_pMutex_create )
		return NULL;

	/* call defined handler */
	return g_pMutex_create( );
}
void les_ssl_mutex_destroy( voidPtr mutex )
{
	if( !g_pMutex_destroy )
		return;

	/* call defined handler */
	g_pMutex_destroy( mutex );
	return;
}
void les_ssl_mutex_lock( voidPtr mutex )
{
	if( !g_pMutex_lock )
		return;

	/* call defined handler */
	g_pMutex_lock( mutex );
	return;
}
void les_ssl_mutex_unlock( voidPtr mutex )
{
	if( !g_pMutex_unlock )
		return;

	/* call defined handler */
	g_pMutex_unlock( mutex );
	return;
}