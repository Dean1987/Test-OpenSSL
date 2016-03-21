#ifndef _LES_SSL_STRING_H
#define _LES_SSL_STRING_H
int les_ssl_cmp( const char* str1 , const char* str2 );
char* les_ssl_string_printfv( const char* chunk , ... );
void les_ssl_string_trim( char* chunk , size_t* trimmed );
#endif