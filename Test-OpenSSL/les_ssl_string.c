#include "../Header.h"
#include "les_ssl_string.h"

int get_vprintf_len( const char * format , va_list args )
{
	if( format == NULL )
		return 0;
	return _vscprintf( format , args ) + 1;
}

char* les_ssl_printfv( const char * chunk , ... )
{
	va_list args;
	char* strResult = NULL;
	/* get the amount of memory to be allocated */
	va_start( args , chunk );
	int nSize = get_vprintf_len( chunk , args );
	va_end( args );

	/* check result */
	if( nSize == -1 )
	{
		les_ssl_print( LES_SSL_LOGGING_ERR | LES_SSL_LOGGING_DEBUG , LES_SSl_FILE , LES_SSl_LINE
			, "unable to calculate the amount of memory for the strdup_printf operation" );
		return NULL;
	} /* end if */

	  /* allocate memory */
	strResult = calloc_new( char , nSize + 2 );

	/* copy current size */

	nSize = _vsnprintf_s( strResult , nSize + 1 , nSize , chunk , args );
	
	return strResult;
}