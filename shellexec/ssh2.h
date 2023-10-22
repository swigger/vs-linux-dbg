#pragma once

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
	int m_sock = -1;
	bool m_bShell = false;
	LIBSSH2_SESSION* m_session = 0;
	LIBSSH2_CHANNEL* m_channel = 0;

public:
	static int connect_host(const Host& host);

	CSSH2(const Host& host);
	~CSSH2();

	int init_conection();
	int run(crefstr cmd);
	int run_shell(crefstr cmd);
	int io_loop();
	int bye();
protected:
	bool wait_socket(int64_t * eow);
	int read(string& con, int64_t * eow, bool readerr=false);
	int write(const char* data, ssize_t len=-1);
};
