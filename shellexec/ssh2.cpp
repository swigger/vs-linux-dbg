#include "stdafx.h"
#include "ssh2.h"
#include <libssh2.h>
#include <WS2tcpip.h>
#include <assert.h>
#pragma comment(lib, "libssh2.lib")

namespace
{
	unsigned int getnb(int sock)
	{
		u_long nr = 0;
		ioctlsocket(sock, FIONREAD, &nr);
		return (unsigned int)nr;
	}
	int poll_socket(int sock, bool want_read, bool want_write, int64_t timeout)
	{
		pollfd pf;
		pf.fd = sock;
		pf.events = 0;
		if (want_read) pf.events |= POLLIN;
		if (want_write) pf.events |= POLLOUT;
		if (pf.events == 0) return 0;
		int rt = WSAPoll(&pf, 1, (int)timeout);
		if (rt == SOCKET_ERROR) {
			return -1;
		}
		if (pf.revents & (POLLHUP | POLLNVAL | POLLERR))
		{
			if ((pf.events & POLLIN) && getnb(sock) > 0)
				return 1; //read available data.
			else
				return -1;
		}
		int ret = 0;
		if (pf.revents & POLLOUT) ret |= 2;
		if (pf.revents & POLLIN) ret |= 1;
		return ret;
	}

	struct tmp_sock_t {
		int sock;
		tmp_sock_t(int s) : sock(s) {}
		~tmp_sock_t() {
			if (sock != -1)	closesocket(sock);
		}
		int detach() {
			int rt = sock;
			sock = -1;
			return rt;
		}
	};
}


CSSH2::CSSH2(const Host & host): m_host(host)
{
}

CSSH2::~CSSH2()
{
	if (m_channel)
	{
		libssh2_channel_free(m_channel);
	}

	if (m_session)
	{
		libssh2_session_disconnect(m_session, "Normal Shutdown");
		libssh2_session_free(m_session);
	}
	if (m_sock)
	{
		closesocket(m_sock);
		m_sock = -1;
	}
}

int CSSH2::connect_host(const Host& host)
{
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(host.port);
	if (inet_pton(AF_INET, host.hostname.c_str(), &sin.sin_addr))
	{
		struct addrinfo hints {};
		hints.ai_family = AF_INET;
		struct addrinfo* result;
		bool done = false;
		if (getaddrinfo(host.hostname.c_str(), NULL, &hints, &result) == 0)
		{
			for (struct addrinfo* rp = result; rp != NULL; rp = rp->ai_next)
			{
				if (rp->ai_family == AF_INET)
				{
					memcpy(&sin.sin_addr, &((struct sockaddr_in*)rp->ai_addr)->sin_addr, sizeof(sin.sin_addr));
					done = 1;
					break;
				}
			}
			freeaddrinfo(result);
		}
		if (!done) {
			return -1;
		}
	}
	int sock = (int) socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		return -1;
	}
	// set non block
	unsigned long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);
	int rt = connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in));
	if (rt == -1) {
		if (WSAGetLastError() != WSAEWOULDBLOCK) {
			closesocket(sock);
			return -1;
		}
		// wait for 10 seconds
		fd_set fd;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		struct timeval tv;
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		rt = select(sock + 1, NULL, &fd, NULL, &tv);
		if (rt <= 0) {
			closesocket(sock);
			return -1;
		}
	}
	return sock;
}

bool CSSH2::wait_socket(int64_t * eow)
{
	int dir = libssh2_session_block_directions(m_session);
	if (eow) {
		if (*eow == 0) return false;
		int64_t timeout = *eow - GetTickCount64();
		if (timeout <= 0) {
			timeout = 0;
			*eow = 0; // dont wait twice if time is up
		}
		return poll_socket(m_sock, !!(dir & LIBSSH2_SESSION_BLOCK_INBOUND), !!(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND), timeout) > 0;
	}
	return poll_socket(m_sock, !!(dir & LIBSSH2_SESSION_BLOCK_INBOUND), !!(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND), -1) > 0;
}

int CSSH2::write(const char* data, ssize_t len)
{
	if (len < 0) len = strlen(data);
	int rc;
	int64_t eow = 0;
	while ((rc = libssh2_channel_write(m_channel, data, len)) == LIBSSH2_ERROR_EAGAIN)
		wait_socket(&(eow = GetTickCount64() + 10000));
	if (rc < 0) {
		std::cerr << "Failed to write command" << std::endl;
		return -1;
	}
	return rc;
}

int CSSH2::read(string& con, int64_t* eow, bool readerr)
{
	char buffer[4096];
	ssize_t rc = 0;
	int delay = 0;
	bool mode_eow = eow && *eow > 0;
	bool mode_delay = eow && (delay = (int)-*eow) > 0;
	int64_t allrd = 0;
	for (;;)
	{
		rc = libssh2_channel_read_ex(m_channel, readerr?1:0, buffer, sizeof(buffer));
		if (rc > 0) {
			con.append(buffer, rc);
			allrd += rc;
			if (mode_delay) continue;
			return 0;
		}
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			if (mode_eow)
			{
				if (wait_socket(eow)) continue;
			}
			else if (mode_delay)
			{
				int64_t eow2 = GetTickCount64() + delay;
				if (wait_socket(&eow2))	continue;
				if (allrd > 0) return (int)allrd;
			}
		}
		if (mode_delay)
			Sleep(0);
		break;
	}
	return (int) rc;
}

int CSSH2::init_conection()
{
	int rc = 0;
	tmp_sock_t sock(connect_host(m_host));
	if (sock.sock < 0) return -1;

	LIBSSH2_SESSION* session = libssh2_session_init();
	if (!session) {
		fprintf(stderr, "libssh2_session_init failed\n");
		return -1;
	}
	m_session = session;

	libssh2_session_set_blocking(session, 0);
	int64_t eow = GetTickCount64() + 20000;
	while ((rc = libssh2_session_handshake(session, sock.sock)) == LIBSSH2_ERROR_EAGAIN)
		wait_socket(&eow);
	if (rc) {
		fprintf(stderr, "Failed to establish SSH session\n");
		libssh2_session_free(session);
		m_session = 0;
		return -1;
	}

	while ((rc = libssh2_userauth_publickey_fromfile(session, m_host.username.c_str(), NULL, m_host.privateFileName.c_str(), NULL)) == LIBSSH2_ERROR_EAGAIN)
		wait_socket(&eow);
	if (rc) {
		fprintf(stderr, "Authentication failed\n");
		libssh2_session_disconnect(session, "Auth Failed");
		libssh2_session_free(session);
		m_session = 0;
		return -1;
	}
	m_sock = sock.detach();
	return 0;
}

int CSSH2::run_shell(crefstr cmd)
{
	int rc;
	if (m_channel == 0)
	{
		LIBSSH2_CHANNEL* channel;
		int64_t eow = GetTickCount64() + 9000;
		while ((channel = libssh2_channel_open_session(m_session)) == NULL && libssh2_session_last_error(m_session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
			wait_socket(&eow);
		if (!channel) {
			std::cerr << "Failed to open channel" << std::endl;
			return -1;
		}

		while ((rc = libssh2_channel_request_pty(channel, "vanilla")) == LIBSSH2_ERROR_EAGAIN)
			wait_socket(&eow);
		if (rc)
		{
			std::cerr << "Failed to request PTY" << std::endl;
			libssh2_channel_free(channel);
			return -1;
		}

		while ((rc = libssh2_channel_shell(channel)) == LIBSSH2_ERROR_EAGAIN)
			wait_socket(&eow);
		if (rc) {
			std::cerr << "Failed to open shell" << std::endl;
			libssh2_channel_free(channel);
			return -1;
		}
		m_channel = channel;
		m_bShell = true;
	}

	if (!cmd.empty())
	{
		string newcmd(cmd);
		newcmd = "cd /kkf\n";
		write(newcmd.data(), newcmd.length());

		string content;
		int64_t eow = -200;
		poll_socket(m_sock, true, 0, 200);
		read(content, &eow, 0);
		printf("%s\n", content.c_str());
		content.clear();
	}
	return 0;
}

int CSSH2::io_loop() {
	// set console non block, noecho
	DWORD mode;
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));
	// read & write
	char buffer[4096];
	ssize_t rc = 0;
	for (;;)
	{
		int64_t eow = GetTickCount64() + 300;
		rc = libssh2_channel_read_ex(m_channel, 0, buffer, sizeof(buffer));
		if (rc > 0) {
			fwrite(buffer, 1, rc, stdout);
		}
		else if (rc == LIBSSH2_ERROR_EAGAIN) {
			if (wait_socket(&eow)) continue;
		}
		else
			break;

		// read console if there is input
		DWORD n;
		INPUT_RECORD rcd;
		if (PeekConsoleInput(hStdin, &rcd, 1, &n) && n > 0)
		{
			ReadConsoleInput(hStdin, &rcd, 1, &n);
			if (rcd.EventType == KEY_EVENT)
			{
				if (rcd.Event.KeyEvent.bKeyDown)
				{
					write(&rcd.Event.KeyEvent.uChar.AsciiChar, 1);
					poll_socket(m_sock, 1, 0, 100);
				}
			}
		}
	}
	return 0;
}

int CSSH2::run(crefstr cmd)
{
	assert(m_channel == 0);
	int rc;
	LIBSSH2_CHANNEL* channel;
	int64_t eow = GetTickCount64() + 9000;
	while ((channel = libssh2_channel_open_session(m_session)) == NULL && libssh2_session_last_error(m_session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN) 
		wait_socket(&eow);

	if (!channel) {
		std::cerr << "Failed to open channel" << std::endl;
		return -1;
	}
	m_channel = channel;

	if (cmd.empty())
	{
		while ((rc = libssh2_channel_shell(channel)) == LIBSSH2_ERROR_EAGAIN)
			wait_socket(&eow);
	}
	else {
		while ((rc = libssh2_channel_exec(channel, cmd.c_str())) == LIBSSH2_ERROR_EAGAIN)
			wait_socket(&eow);
	}

	string content;
	eow = -5000;
	read(content, &eow, 0);
	printf("%s\n", content.c_str());
	read(content, &eow, 1);
	printf("== %s\n", content.c_str());
	return 0;
}

int CSSH2::bye() {
	if (m_channel) {
		int64_t eow = GetTickCount64() + 3000;
		if (m_bShell)
			write("\003\004", 2);
		while (libssh2_channel_send_eof(m_channel) == LIBSSH2_ERROR_EAGAIN)
			wait_socket(&eow);
		libssh2_session_set_timeout(m_session, 3000);
		libssh2_channel_wait_eof(m_channel);
		libssh2_channel_wait_closed(m_channel);
		libssh2_channel_free(m_channel);
		m_channel = 0;
	}
	return 0;
}