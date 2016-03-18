#ifndef _LES_SSL_ENUM_H
#define _LES_SSL_ENUM_H

typedef enum
{
	/**
	* @brief Unknown role, returned/used when the connection isn't defined.
	*/
	LES_SSL_ROLE_UNKNOWN ,
	/**
	* @brief When the connection was created connecting to a web
	* socket server (see \ref LES_SSL_conn_new).
	*/
	LES_SSL_ROLE_CLIENT ,
	/**
	* @brief When the connection was accepted being a listener
	* process.
	*/
	LES_SSL_ROLE_LISTENER ,
	/**
	* @brief When the connection was created by \ref
	* LES_SSL_listener_new to accept incoming connections.
	*/
	LES_SSL_ROLE_MAIN_LISTENER
}LES_SSL_Role;

/**
* @brief SSL/TLS protocol type to use for the client or listener
* connection.
*/
typedef enum
{
	/**
	* @brief Allows to define SSLv23 as SSL protocol used by the
	* client or server connection. A TLS/SSL connection
	* established with these methods may understand SSLv3, TLSv1,
	* TLSv1.1 and TLSv1.2 protocols (\ref LES_SSL_METHOD_SSLV3, \ref LES_SSL_METHOD_TLSV1, ...)
	*/
	LES_SSL_METHOD_SSLV23 = 2 ,
	/**
	* @brief Allows to define SSLv3 as SSL protocol used by the
	* client or server connection. A connection/listener
	* established with this method will only understand this
	* method.
	*/
	LES_SSL_METHOD_SSLV3 = 3 ,
	/**
	* @brief Allows to define TLSv1 as SSL protocol used by the
	* client or server connection. A connection/listener
	* established with this method will only understand this
	* method.
	*/
	LES_SSL_METHOD_TLSV1 = 4 ,
#if defined(TLSv1_1_client_method)
	/**
	* @brief Allows to define TLSv1.1 as SSL protocol used by the
	* client or server connection. A connection/listener
	* established with this method will only understand this
	* method.
	*/
	LES_SSL_METHOD_TLSV1_1 = 5
#endif
} SslProtocol ;
#endif
