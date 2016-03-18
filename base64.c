#include "Header.h"
#include "Test-OpenSSL/les_ssl_struct.h"

bool les_ssl_ncmp( const char * string1 , const char * string2 , int bytes )
{
	int iterator;
	if( bytes <= 0 )
		return false;
	if( string1 == NULL && string2 == NULL )
		return true;
	if( string1 == NULL || string2 == NULL )
		return false;

	/* next position */
	iterator = 0;
	while( string1[iterator] &&
		string2[iterator] &&
		iterator < bytes )
	{
		if( string1[iterator] != string2[iterator] )
			return false;
		iterator++;
	} /* end while */

	  /* last check, ensure both ends with 0 */
	return iterator == bytes;
}
bool base64_encode( const char* strContent , int nLen ,
                         char* strOutput , size_t* sOutput )
{
    BIO* b64 = NULL;
    BIO* bMem = NULL;
    BUF_MEM* bPtr = NULL;

    if( strContent == NULL || strOutput == NULL || nLen <= 0
        || sOutput == NULL)
        return false;

    b64 = BIO_new( BIO_f_base64( ) );
    bMem = BIO_new( BIO_s_mem( ) );

	//Push
	b64 = BIO_push( b64 , bMem );

	if( BIO_write( b64 , strContent , nLen ) != nLen )
	{
		BIO_free_all( b64 );
		return false;
	}

	if( BIO_flush( b64 ) != 1 )
	{
		BIO_free_all( b64 );
		return false;
	}

	//now get content
	BIO_get_mem_ptr( b64 , &bPtr );

	//check output size
	if( ( *sOutput ) < bPtr->length )
	{
		*sOutput = bPtr->length;
		return false;
	}

	memcpy( strOutput , bPtr->data , bPtr->length - 1 );
	strOutput[bPtr->length - 1] = '\0';

	BIO_free_all( b64 );
    return true;
}

bool base64_decode( const char* strContent , int nLen , char* strOutput , int* sOutput )
{
	BIO* b64 = NULL;
	BIO* bMem = NULL;

	if( strContent == NULL || strOutput == NULL || nLen <= 0 || sOutput == NULL )
		return false;

	/* create bio */
	bMem = BIO_new_mem_buf( ( void * ) strContent , nLen );
	b64 = BIO_new( BIO_f_base64( ) );
	BIO_set_flags( b64 , BIO_FLAGS_BASE64_NO_NL );

	/* push */
	bMem = BIO_push( b64 , bMem );

	*sOutput = BIO_read( bMem , strOutput , *sOutput );
	strOutput[*sOutput] = 0;

	BIO_free_all( bMem );

	return true;
}
