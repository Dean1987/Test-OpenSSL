#include "../Header.h"
#include "les_ssl_string.h"

int get_vprintf_len( const char* format , va_list args )
{
	if( format == NULL )
		return 0;
	return _vscprintf( format , args ) + 1;
}

char* les_ssl_string_printfv( const char* chunk , ... )
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
void les_ssl_string_trim( char* chunk , size_t* trimmed )
{
	int iterator = 0;
	int iterator2 = 0;
	size_t    end = 0;
	size_t    total = 0;

	/* perform some environment check */
	if( chunk == NULL )
		return;

	/* check empty string received */
	if( strlen( chunk ) == 0 )
	{
		if( trimmed )
			*trimmed = 0;
		return;
	}

	/* check the amount of white spaces to remove from the
	* begin */
	iterator = 0;
	while( chunk[iterator] != 0 )
	{

		/* check that the iterator is not pointing to a white
		* space */
		if( !isspace( *(chunk + iterator ) ) )
			break;

		/* update the iterator */
		iterator++;
	}

	/* check for the really basic case where an empty string is found */
	if( iterator == ( int ) strlen( chunk ) )
	{
		/* an empty string, trim it all */
		chunk[0] = 0;
		if( trimmed )
			*trimmed = iterator;
		return;
	} /* end if */

	  /* now get the position for the last valid character in the
	  * chunk */
	total = strlen( chunk ) - 1;
	end = total;
	while( chunk[end] != 0 )
	{

		/* stop if a white space is found */
		if( !isspace( *( chunk + end ) ) )
			break;

		/* update the iterator to eat the next white space */
		end--;
	}

	/* the number of items trimmed */
	total -= end;
	total += iterator;

	/* copy the exact amount of non white spaces items */
	iterator2 = 0;
	while( iterator2 < ( end - iterator + 1 ) )
	{
		/* copy the content */
		chunk[iterator2] = chunk[iterator + iterator2];

		/* update the iterator */
		iterator2++;
	}
	chunk[end - iterator + 1] = 0;

	if( trimmed != NULL )
		*trimmed = total;

	/* return the result reference */
	return;
}