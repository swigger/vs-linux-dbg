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
	static string read_console(fd_t fd);
	CSSH2(const Host& host);
	~CSSH2();

	future<int> init_conection();
	future<int> run(crefstr cmd);
	future<int> run_shell(crefstr cmd);
	future<int> io_loop();
	future<int> bye();
protected:
	virtual void hack_command(string& cmd) {}
	future<int> wait_socket(int64_t * eow, fd_t sock=-1);
	// if *eow > 0, read any until *eow.
	// if *eow < 0, read any until no data in (-*eow) ms.
	// if *eow = 0, read just once, returns the number of bytes read/error code if < 0.
	// if eow == 0, read until there is something to read/error code if < 0.
	future<int> ssh_read(string& con, int64_t * eow, bool readerr=false);
	future<int> ssh_write(const char* data, ssize_t len=-1);
};
