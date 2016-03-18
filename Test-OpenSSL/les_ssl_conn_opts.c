#include "les_ssl_struct.h"
#include "les_ssl_context.h"
#include "les_ssl_conn_opts.h"

void les_ssl_conn_opts_free( LES_SSL_ConnOpts * opts )
{
	if( opts == NULL )
		return;

	/* acquire here the mutex */
	les_ssl_mutex_lock( opts->pMutex );
	opts->nRefs--;
	if( opts->nRefs != 0 )
	{
		/* release here the mutex */
		les_ssl_mutex_unlock( opts->pMutex );
		return;
	}
	/* release here the mutex */
	les_ssl_mutex_unlock( opts->pMutex );

	free( opts->strCertificate );
	free( opts->strPrivate_key );
	free( opts->strChain_certificate );
	free( opts->strCa_certificate );

	/* cookie */
	free( opts->strCookie );

	/* release mutex */
	les_ssl_mutex_destroy( opts->pMutex );
	free( opts );
	return;
}

void les_ssl_conn_opts_release( LES_SSL_ConnOpts* options )
{
	if( options == NULL )
		return;
	if( options->bReuse )
		return;
	les_ssl_conn_opts_free( options );
	return;
}