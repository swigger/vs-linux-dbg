#pragma once
#include "sync/coco2.h"

typedef struct _LIBSSH2_SESSION                     LIBSSH2_SESSION;
typedef struct _LIBSSH2_CHANNEL                     LIBSSH2_CHANNEL;

class CSSH2
{
public:
	struct Host {
		std::string hostname;
		int port;
		string fingerprint;
		string username;
		string authenticationMethod;
		string privateFileName;
		string passphrase;
	};

protected:
	Host m_host;
	fd_t m_sock = -1;
	bool m_bShell = false;
	LIBSSH2_SESSION* m_session = 0;
	LIBSSH2_CHANNEL* m_channel = 0;

public:
	CSSH2(const Host& host);
	~CSSH2();

	future<int> init_conection();
	future<int> run(crefstr cmd);
	future<int> run_shell(crefstr cmd);
	future<int> io_loop();
	future<int> bye();
protected:
	future<bool> wait_socket(int64_t * eow, fd_t sock=-1);
	future<int> read(string& con, int64_t * eow, bool readerr=false);
	future<int> write(const char* data, ssize_t len=-1);
};
