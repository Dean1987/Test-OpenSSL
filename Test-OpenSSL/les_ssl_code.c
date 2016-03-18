#include "../Header.h"
#include "les_ssl_struct.h"
#include "les_ssl_code.h"

void set_bit( char * buffer , int position )
{
	buffer[0] |= ( 1 << position );
	return;
}

void set_16bit( int value , char * buffer )
{
	buffer[0] = ( value & 0x0000ff00 ) >> 8;
	buffer[1] = value & 0x000000ff;
}

void set_32bit( int value , char * buffer )
{
	buffer[0] = ( value & 0x00ff000000 ) >> 24;
	buffer[1] = ( value & 0x0000ff0000 ) >> 16;
	buffer[2] = ( value & 0x000000ff00 ) >> 8;
	buffer[3] = value & 0x00000000ff;
}

int get_32bit( const char * buffer )
{
	int part1 = ( int ) ( buffer[0] & 0x0ff ) << 24;
	int part2 = ( int ) ( buffer[1] & 0x0ff ) << 16;
	int part3 = ( int ) ( buffer[2] & 0x0ff ) << 8;
	int part4 = ( int ) ( buffer[3] & 0x0ff );

	return part1 | part2 | part3 | part4;
}

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
