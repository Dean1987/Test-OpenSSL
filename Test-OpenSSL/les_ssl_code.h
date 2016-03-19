#ifndef _LES_SSL_CODE_H
#define _LES_SSL_CODE_H
#include "../Header.h"
void set_bit( char * buffer , int position );
void set_16bit( int value , char * buffer );
void set_32bit( int value , char * buffer );
int get_32bit( const char * buffer );

bool base64_encode( const char* strContent , int nLen , char* strOutput , size_t* sOutput );
bool base64_decode( const char* strContent , int nLen , char* strOutput , int* sOutput );
#endif
