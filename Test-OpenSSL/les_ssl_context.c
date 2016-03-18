#include "les_ssl_struct.h"
#include "les_ssl_context.h"

/**
* @brief Creates an empty Nopoll context.
*/
LES_SSL_Context* les_ssl_context_new( )
{
	LES_SSL_Context* result = calloc_new( LES_SSL_Context , 1 );
	if( result == NULL )
		return NULL;

	/* set initial reference */
	result->nConn_id = 1;
	result->nRefs = 1;

	/* 20 seconds for connection timeout */
	result->lConn_connect_std_timeout = 20000000;

	/* default log initialization */
	result->bNot_executed = true;
	result->bDebug_enabled = false;

	/* colored log */
	result->bNot_executed_color = true;
	result->bDebug_color_enabled = false;

	/* default back log */
	result->nBacklog = 5;

	/* current list length */
	result->nConn_length = 0;

	/* setup default protocol version */
	result->nProtocol_version = 13;

	/* create mutexes */
	result->pRef_mutex = les_ssl_mutex_create( );

	return result;
}

void les_ssl_ctx_unref( LES_SSL_Context* ctx )
{
	Certificate* pCert;
	int iterator;

	/* acquire mutex here */
	les_ssl_mutex_lock( ctx->pRef_mutex );

	ctx->nRefs--;
	if( ctx->nRefs != 0 )
	{
		/* release mutex here */
		les_ssl_mutex_unlock( ctx->pRef_mutex );
		return;
	}
	/* release mutex here */
	les_ssl_mutex_unlock( ctx->pRef_mutex );

	iterator = 0;
	while( iterator < ctx->nCertificates_length )
	{
		/* get reference */
		pCert = &( ctx->pCertificates[iterator] );

		/* release */
		free( pCert->strServerName );
		free( pCert->strCertificateFile );
		free( pCert->strPrivateKey );
		free( pCert->strOptionalChainFile );

		/* next position */
		iterator++;
	} /* end while */

	  /* release mutex */
	les_ssl_mutex_destroy( ctx->pRef_mutex );

	/* release all certificates buckets */
	free( ctx->pCertificates );

	/* release connection */
	free( ctx->pConn_list );
	ctx->nConn_length = 0;
	free( ctx );
	return;
}
int les_ssl_ctx_conns( LES_SSL_Context * ctx )
{
	return ctx->nConn_num;
}
void les_ssl_ctx_unregister_conn( LES_SSL_Context* pCtx , LES_SSL_Conn* pConn )
{
	int nIterator = 0;

	if( pCtx == NULL || pConn == NULL )
		return;

	/* acquire mutex here */
	les_ssl_mutex_lock( pCtx->pRef_mutex );

	/* find the connection and remove it from the array */
	nIterator = 0;
	while( nIterator < pCtx->nConn_length )
	{

		/* check the connection reference */
		if( pCtx->pConn_list && pCtx->pConn_list[nIterator] && pCtx->pConn_list[nIterator]->nId == pConn->nId )
		{
			/* remove reference */
			pCtx->pConn_list[nIterator] = NULL;

			/* update connection list number */
			pCtx->nConn_num--;

			/* release */
			nopoll_mutex_unlock( pCtx->pRef_mutex );

			/* acquire a reference to the conection */
			nopoll_conn_unref( pConn );

			break;
		}

		nIterator++;
	}

	  /* release mutex here */
	les_ssl_mutex_unlock( pCtx->pRef_mutex );

	return;
}