#include "../Header.h"
#include "les_ssl_struct.h"
#include "les_ssl_lock.h"

void les_ssl_msg_unref( LES_SSL_Msg* pMsg )
{
	if( pMsg == NULL )
		return;

	/* acquire mutex here */
	les_ssl_mutex_lock( pMsg->pRef_mutex );

	pMsg->nRefs--;
	if( pMsg->nRefs != 0 )
	{
		/* release mutex here */
		les_ssl_mutex_unlock( pMsg->pRef_mutex );
		return;
	}
	/* release mutex */
	les_ssl_mutex_unlock( pMsg->pRef_mutex );
	les_ssl_mutex_destroy( pMsg->pRef_mutex );

	/* free websocket message */
	free( pMsg->pPayload );
	free( pMsg );

	/* release mutex here */
	return;
}