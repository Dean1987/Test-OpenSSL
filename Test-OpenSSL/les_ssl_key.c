#include "../Header.h"
#include "les_ssl_struct.h"
#include "les_ssl_key.h"

char* les_ssl_produce_accept_key( LES_SSL_Context* pCtx , const char* strWebsocket_key )
{
	const char* strStatic_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	char* strAccept_key = NULL;
	size_t nAccept_key_size = 0;
	size_t nKey_length = 0;

	if( strWebsocket_key == NULL )
		return NULL;

	nKey_length = strlen( strWebsocket_key );

	unsigned char strBuffer[EVP_MAX_MD_SIZE];
	EVP_MD_CTX sMdctx;
	const EVP_MD* pMd = NULL;
	unsigned int nMd_len = EVP_MAX_MD_SIZE;

	nAccept_key_size = nKey_length + 36 + 1;
	strAccept_key = calloc_new( char , nAccept_key_size );

	memcpy( strAccept_key , strWebsocket_key , nKey_length );
	memcpy( strAccept_key + nKey_length , strStatic_guid , 36 );

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "base key value: %s" , strAccept_key );

	/* now sha-1 */
	pMd = EVP_sha1( );
	EVP_DigestInit( &sMdctx , pMd );
	EVP_DigestUpdate( &sMdctx , strAccept_key , strlen( strAccept_key ) );
	EVP_DigestFinal( &sMdctx , strBuffer , &nMd_len );

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE , "Sha-1 length is: %u" , nMd_len );
	/* now convert into base64 */
	if( !base64_encode( ( const char * ) strBuffer , nMd_len , strAccept_key , &nAccept_key_size ) )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			 , "Failed to base64 sec-websocket-key value.." );
		return NULL;
	}

	les_ssl_print( LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
		, "Returning Sec-Websocket-Accept: %s" , strAccept_key );

	return strAccept_key;

}