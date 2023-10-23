#include "stdafx.h"
#include "ssh2.h"
#include "base/log.h"
#include <libssh2.h>
#include <WS2tcpip.h>
#include <assert.h>
#pragma comment(lib, "libssh2.lib")

namespace
{
	struct tmp_sock_t {
		fd_t sock;
		tmp_sock_t(fd_t s) : sock(s) {}
		~tmp_sock_t() {
			if (sock != -1)	closesocket(sock);
		}
		fd_t detach() {
			fd_t rt = sock;
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

future<bool> CSSH2::wait_socket(int64_t * eow, fd_t sock)
{
	if (sock < 0) sock = m_sock;
	assert(sock > 0);
	int dir = libssh2_session_block_directions(m_session);
	uint32_t time_to = eow ? coio::time_to(GetTickCount64(), *eow) : INFINITE;
	int flag = 0;
	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		flag |= co_await coio::io_read(sock, time_to);
	if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		flag |= co_await coio::io_write(sock, time_to);
	bool rr = (flag & (CCoContainer2::user::UF_READABLE| CCoContainer2::user::UF_WRITABLE)) != 0;
	co_return rr;
}

future<int> CSSH2::write(const char* data, ssize_t len)
{
	if (len < 0) len = strlen(data);
	ssize_t rc;
	int64_t eow = 0;
	while ((rc = libssh2_channel_write(m_channel, data, len)) == LIBSSH2_ERROR_EAGAIN)
		co_await wait_socket(&(eow = GetTickCount64() + 10000));
	if (rc < 0) {
		Log::error("Failed to write command");
		co_return -1;
	}
	co_return (int)rc;
}

future<int> CSSH2::read(string& con, int64_t* eow, bool readerr)
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
			co_return 0;
		}
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			if (mode_eow)
			{
				if (co_await wait_socket(eow)) continue;
			}
			else if (mode_delay)
			{
				int64_t eow2 = GetTickCount64() + delay;
				if (co_await wait_socket(&eow2)) continue;
				if (allrd > 0) co_return (int)allrd;
			}
		}
		if (mode_delay)
			Sleep(0);
		break;
	}
	co_return (int) rc;
}

future<int> CSSH2::init_conection()
{
	int rc = 0;
	tmp_sock_t sock(co_await coio::connect(m_host.hostname.c_str(), m_host.port, 15000));
	if (sock.sock < 0) co_return -1;

	LIBSSH2_SESSION* session = libssh2_session_init();
	if (!session) {
		fprintf(stderr, "libssh2_session_init failed\n");
		co_return -1;
	}
	m_session = session;

	libssh2_session_set_blocking(session, 0);
	int64_t eow = GetTickCount64() + 20000;
	while ((rc = libssh2_session_handshake(session, sock.sock)) == LIBSSH2_ERROR_EAGAIN)
		co_await wait_socket(&eow, sock.sock);
	if (rc) {
		fprintf(stderr, "Failed to establish SSH session\n");
		libssh2_session_free(session);
		m_session = 0;
		co_return -1;
	}

	while ((rc = libssh2_userauth_publickey_fromfile(session, m_host.username.c_str(), NULL, m_host.privateFileName.c_str(), NULL)) == LIBSSH2_ERROR_EAGAIN)
		co_await wait_socket(&eow, sock.sock);
	if (rc) {
		fprintf(stderr, "Authentication failed\n");
		libssh2_session_disconnect(session, "Auth Failed");
		libssh2_session_free(session);
		m_session = 0;
		co_return -1;
	}
	m_sock = sock.detach();
	co_return 0;
}

future<int> CSSH2::run_shell(crefstr cmd)
{
	int rc;
	if (m_channel == 0)
	{
		LIBSSH2_CHANNEL* channel;
		int64_t eow = GetTickCount64() + 9000;
		while ((channel = libssh2_channel_open_session(m_session)) == NULL && libssh2_session_last_error(m_session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
		if (!channel) {
			std::cerr << "Failed to open channel" << std::endl;
			co_return -1;
		}

		while ((rc = libssh2_channel_request_pty(channel, "vanilla")) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
		if (rc)
		{
			std::cerr << "Failed to request PTY" << std::endl;
			libssh2_channel_free(channel);
			co_return -1;
		}

		while ((rc = libssh2_channel_shell(channel)) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
		if (rc) {
			std::cerr << "Failed to open shell" << std::endl;
			libssh2_channel_free(channel);
			co_return -1;
		}
		m_channel = channel;
		m_bShell = true;
	}

	if (!cmd.empty())
	{
		string newcmd(cmd);
		newcmd = "cd /kkf\n";
		co_await write(newcmd.data(), newcmd.length());

		string content;
		int64_t eow = -200;
		if (co_await coio::io_read(m_sock, 200) & CCoContainer2::user::UF_READABLE)
		{
			co_await read(content, &eow, 0);
			printf("%s", content.c_str());
			fflush(stdout);
		}
	}
	co_return 0;
}

future<int> CSSH2::io_loop()
{
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
			if (co_await wait_socket(&eow)) continue;
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
					co_await write(&rcd.Event.KeyEvent.uChar.AsciiChar, 1);
					co_await coio::io_read(m_sock, 100);
				}
			}
		}
	}
	Log::debug("ssh2 session DONE");
	co_return 0;
}

future<int> CSSH2::run(crefstr cmd)
{
	assert(m_channel == 0);
	int rc;
	LIBSSH2_CHANNEL* channel;
	int64_t eow = GetTickCount64() + 9000;
	while ((channel = libssh2_channel_open_session(m_session)) == NULL && libssh2_session_last_error(m_session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN) 
		co_await wait_socket(&eow);

	if (!channel) {
		Log::error("Failed to open channel");
		co_return -1;
	}
	m_channel = channel;

	if (cmd.empty())
	{
		while ((rc = libssh2_channel_shell(channel)) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
	}
	else {
		while ((rc = libssh2_channel_exec(channel, cmd.c_str())) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
	}

	string content;
	eow = -5000;
	co_await read(content, &eow, 0);
	printf("%s\n", content.c_str());
	co_await read(content, &eow, 1);
	printf("== %s\n", content.c_str());
	co_return 0;
}

future<int> CSSH2::bye() {
	if (m_channel) {
		int64_t eow = GetTickCount64() + 3000;
		if (m_bShell)
			co_await write("\003\004", 2);
		while (libssh2_channel_send_eof(m_channel) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
		libssh2_session_set_timeout(m_session, 3000);
		while (libssh2_channel_wait_eof(m_channel) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
		libssh2_channel_wait_closed(m_channel);
		libssh2_channel_free(m_channel);
		m_channel = 0;
	}
	co_return 0;
}