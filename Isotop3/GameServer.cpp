#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include "util.h"

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

typedef struct
{
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
} DTLSParams;

typedef int socklen_t;

void DTLS_Error(const char *Format, ...)
{
	va_list va;
	va_start(va, Format);

	char buffer[4096];
	vsprintf_s(buffer, Format, va);

	va_end(va);

	MessageBoxA(nullptr, buffer, "", 0);
}

bool dtls_InitContextFromKeystore(DTLSParams *params, const char *keyname)
{
	// Create a new context using DTLS
	params->ctx = SSL_CTX_new(DTLS_method());

	if (!params->ctx)
	{
		DTLS_Error("Error: Cannot create SSL_CTX");
		ERR_print_errors_fp(stderr);

		return false;
	}

	// Set our supported ciphers
	int result = SSL_CTX_set_cipher_list(params->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

	if (result != 1)
	{
		DTLS_Error("Error: cannot set the cipher list");
		ERR_print_errors_fp(stderr);

		return false;
	}

	// The client doesn't have to send its certificate
	SSL_CTX_set_verify(params->ctx, SSL_VERIFY_NONE, nullptr);

	// Load key and certificate
	char certfile[1024];
	char keyfile[1024];
	sprintf_s(certfile, "./%s-cert.pem", keyname);
	sprintf_s(keyfile, "./%s-key.pem", keyname);

	// Load the certificate file; contains also the public key
	result = SSL_CTX_use_certificate_file(params->ctx, certfile, SSL_FILETYPE_PEM);

	if (result != 1)
	{
		DTLS_Error("Error: cannot load certificate file");
		ERR_print_errors_fp(stderr);

		return false;
	}

	// Load private key
	result = SSL_CTX_use_PrivateKey_file(params->ctx, keyfile, SSL_FILETYPE_PEM);

	if (result != 1)
	{
		DTLS_Error("Error: cannot load private key file");
		ERR_print_errors_fp(stderr);

		return false;
	}

	// Check if the private key is valid
	result = SSL_CTX_check_private_key(params->ctx);

	if (result != 1)
	{
		DTLS_Error("Error: checking the private key failed. \n");
		ERR_print_errors_fp(stderr);

		return false;
	}

	return true;
}

int dtls_InitServer(DTLSParams* params)
{
	params->bio = BIO_new_ssl_connect(params->ctx);

	if (params->bio == NULL) {
		fprintf(stderr, "error connecting with BIOs\n");
		return -1;
	}

	BIO_get_ssl(params->bio, &params->ssl);

	if (params->ssl == NULL) {
		fprintf(stderr, "error, exit\n");
		return -1;
	}

	SSL_set_accept_state(params->ssl);

	return 0;
}

struct pass_info
{
	union {
		struct sockaddr_in s4;
	} server_addr, client_addr;
	SSL *ssl;
};

#define BUFFER_SIZE          (1<<16)
typedef __int64 ssize_t;	// Signed size_t
#define INET6_ADDRSTRLEN 46	// Probably right

DWORD WINAPI connection_handle(LPVOID *info) {
	ssize_t len;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct pass_info *pinfo = (struct pass_info*) info;
	SSL *ssl = pinfo->ssl;
	int fd, reading = 0, ret;
	const int on = 1, off = 0;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;

	OPENSSL_assert(pinfo->client_addr.s4.sin_family == pinfo->server_addr.s4.sin_family);
	fd = socket(pinfo->client_addr.s4.sin_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		goto cleanup;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, (socklen_t) sizeof(on));
	bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in));
	connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in));

	// Set new fd and set BIO to connected
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr.s4);

	// Finish handshake
	do { ret = SSL_accept(ssl); } while (ret == 0);
	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		goto cleanup;
	}

	// Set and activate timeouts
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) && num_timeouts < max_timeouts) {

		reading = 1;
		while (reading) {
			len = SSL_read(ssl, buf, sizeof(buf));

			switch (SSL_get_error(ssl, len)) {
			case SSL_ERROR_NONE:
				reading = 0;
				break;
			case SSL_ERROR_WANT_READ:
				// Handle socket timeouts
				if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
					num_timeouts++;
					reading = 0;
				}
				// Just try again
				break;
			case SSL_ERROR_ZERO_RETURN:
				reading = 0;
				break;
			case SSL_ERROR_SYSCALL:
				printf("Socket read error: ");
				reading = 0;
				break;
			case SSL_ERROR_SSL:
				printf("SSL read error: ");
				printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
				goto cleanup;
				break;
			default:
				printf("Unexpected error while reading!\n");
				goto cleanup;
				break;
			}
		}

		if (len > 0) {
			len = SSL_write(ssl, buf, len);

			switch (SSL_get_error(ssl, len)) {
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_WANT_WRITE:
				break;
			case SSL_ERROR_WANT_READ:
				// continue with reading
				break;
			case SSL_ERROR_SYSCALL:
				printf("Socket write error: ");
				//reading = 0;
				break;
			case SSL_ERROR_SSL:
				printf("SSL write error: ");
				printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
				goto cleanup;
				break;
			default:
				printf("Unexpected error while writing!\n");
				goto cleanup;
				break;
			}
		}
	}

	SSL_shutdown(ssl);

cleanup:
	closesocket(fd);
	free(info);
	SSL_free(ssl);
	ExitThread(0);
}


void CreateOpenSSLServer()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	DTLSParams server;

	// Initialize the DTLS context from the key store and then create the server
	// SSL state.
	if (!dtls_InitContextFromKeystore(&server, "server"))
	{
		MessageBoxA(nullptr, "f1", "", 0);
		exit(EXIT_FAILURE);
	}

	if (dtls_InitServer(&server) < 0)
	{
		MessageBoxA(nullptr, "f2", "", 0);
		exit(EXIT_FAILURE);
	}

	FILE *f = fopen("C:\\sslerr.txt", "w");
	setvbuf(f, nullptr, _IONBF, 0);

	//
	// Socket initialization on port 3000
	//
	sockaddr_in inAddr;
	memset(&inAddr, 0, sizeof(inAddr));

	inAddr.sin_family = AF_INET;
	inAddr.sin_port = htons(3000);
	inAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	SOCKET serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (serverSocket == SOCKET_ERROR)
	{
		MessageBoxA(nullptr, "Bad socket", "", 0);
		exit(EXIT_FAILURE);
	}

	int on = 1;
	setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

	// Loop forever accepting messages from the clientSocket, printing their messages,
	// and then terminating their connections
	if (bind(serverSocket, (sockaddr *)&inAddr, sizeof(inAddr)) != 0)
	{
		MessageBoxA(nullptr, "f1", "", 0);
		exit(EXIT_FAILURE);
	}

	// Loop forever, accepting clients
	while (true)
	{
		BIO *bio = BIO_new_dgram(serverSocket, BIO_NOCLOSE);
		SSL *ssl = SSL_new(server.ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		// Wait for the next client
		sockaddr_in clientAddr;
		while (DTLSv1_listen(ssl, (BIO_ADDR *)&clientAddr) <= 0);

		pass_info *info = (pass_info *)malloc(sizeof(pass_info));
		memcpy(&info->server_addr, &inAddr, sizeof(inAddr));
		memcpy(&info->client_addr, &clientAddr, sizeof(clientAddr));
		info->ssl = ssl;

		if (CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)connection_handle, info, 0, nullptr) == NULL)
		{
			MessageBoxA(nullptr, "f2", "", 0);
			exit(-1);
		}
	}
}