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

	__thread uint32_t saved_char;
	static string translate(KEY_EVENT_RECORD& rcd)
	{
		string s;
		switch (rcd.wVirtualKeyCode)
		{
		case VK_RETURN: s = "\n"; break;
		case VK_BACK: s = "\b"; break;
		case VK_TAB: s = "\t"; break;
		case VK_ESCAPE: s = "\x1b"; break;
		case VK_SPACE: s = " "; break;
		case VK_UP: s = "\x1b[A"; break;
		case VK_DOWN: s = "\x1b[B"; break;
		case VK_LEFT: s = "\x1b[D"; break;
		case VK_RIGHT: s = "\x1b[C"; break;
		case VK_DELETE: s = "\x1b[3~"; break;
		case VK_HOME: s = "\x1b[1~"; break;
		case VK_END: s = "\x1b[4~"; break;
		case VK_PRIOR: s = "\x1b[5~"; break;
		case VK_NEXT: s = "\x1b[6~"; break;
		case VK_F1: s = "\x1b[11~"; break;
		case VK_F2: s = "\x1b[12~"; break;
		case VK_F3: s = "\x1b[13~"; break;
		case VK_F4: s = "\x1b[14~"; break;
		case VK_F5: s = "\x1b[15~"; break;
		case VK_F6: s = "\x1b[17~"; break;
		case VK_F7: s = "\x1b[18~"; break;
		case VK_F8: s = "\x1b[19~"; break;
		case VK_F9: s = "\x1b[20~"; break;
		case VK_F10: s = "\x1b[21~"; break;
		case VK_F11: s = "\x1b[23~"; break;
		case VK_F12: s = "\x1b[24~"; break;
		case VK_F13: s = "\x1b[25~"; break;
		case VK_F14: s = "\x1b[26~"; break;
		case VK_F15: s = "\x1b[28~"; break;
		case VK_F16: s = "\x1b[29~"; break;
		case VK_F17: s = "\x1b[31~"; break;
		case VK_F18: s = "\x1b[32~"; break;
		case VK_F19: s = "\x1b[33~"; break;
		case VK_F20: s = "\x1b[34~"; break;
		case VK_F21: s = "\x1b[23~";
		default:
			if (rcd.uChar.UnicodeChar)
			{
				unsigned char buf[4];
				unsigned int uch = rcd.uChar.UnicodeChar;
				int i = 0;
				if (uch >= 0xd800 && uch <= 0xdbff)
				{
					saved_char = uch;
					return "";
				}
				else if (uch >= 0xdc00 && uch <= 0xdfff)
				{
					if (saved_char)
						uch = ((saved_char - 0xd800) << 10) + (uch - 0xdc00) + 0x10000;
					else return "";
				}
				else
				{
					saved_char = 0;
				}

				if (uch < 0x80) buf[i++] = (uint8_t)uch;
				else if (uch < 0x800)
				{
					buf[i++] = (uint8_t)(0xc0 | (uch >> 6));
					buf[i++] = (uint8_t)(0x80 | (uch & 0x3f));
				}
				else if (uch < 0x10000)
				{
					buf[i++] = (uint8_t)(0xe0 | (uch >> 12));
					buf[i++] = (uint8_t)(0x80 | ((uch >> 6) & 0x3f));
					buf[i++] = (uint8_t)(0x80 | (uch & 0x3f));
				}
				else if (uch < 0x200000)
				{
					buf[i++] = (uint8_t)(0xf0 | (uch >> 18));
					buf[i++] = (uint8_t)(0x80 | ((uch >> 12) & 0x3f));
					buf[i++] = (uint8_t)(0x80 | ((uch >> 6) & 0x3f));
					buf[i++] = (uint8_t)(0x80 | (uch & 0x3f));
				}
				s.append((char*)buf, i);
			}
			else
			{
				s = rcd.uChar.AsciiChar;
			}
			break;
		}
		return s;
	}
}

string CSSH2::read_console(fd_t fd)
{
	string ret;
	for (;;)
	{
		DWORD n = 0;
		INPUT_RECORD rcd;
		PeekConsoleInput((HANDLE)fd, &rcd, 1, &n);
		if (n != 1) break;
		ReadConsoleInput((HANDLE)fd, &rcd, 1, &n);
		if (rcd.EventType == KEY_EVENT)
		{
			if (rcd.Event.KeyEvent.bKeyDown)
			{
				ret += translate(rcd.Event.KeyEvent);
			}
		}
	}
	return ret;
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

future<int> CSSH2::wait_socket(int64_t * eow, fd_t sock)
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
	if (flag & CCoContainer2::user::UF_VAR_CHG) co_return -99;
	bool rr = (flag & (CCoContainer2::user::UF_READABLE| CCoContainer2::user::UF_WRITABLE)) != 0;
	co_return rr ? 1 : 0;
}

future<int> CSSH2::ssh_write(const char* data, ssize_t len)
{
	if (len < 0) len = strlen(data);
	ssize_t rc;
	int64_t eow = 0;
	while ((rc = libssh2_channel_write(m_channel, data, len)) == LIBSSH2_ERROR_EAGAIN)
		co_await wait_socket(&(eow = GetTickCount64() + 10000));
	if (rc < 0) {
		char* ermsg = 0;
		libssh2_session_last_error(m_session, &ermsg, 0, 0);
		Log::error("Failed to write %d bytes command: %d,%s", (int)len, rc, ermsg);
		co_return -1;
	}
	co_return (int)rc;
}

future<int> CSSH2::ssh_read(string& con, int64_t* eow, bool readerr)
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
		if (rc == 0)
		{
			rc = libssh2_channel_flush_ex(m_channel, readerr ? 1 : 0);
			int q = libssh2_channel_eof(m_channel);
			if (q) rc = LIBSSH2_ERROR_CHANNEL_CLOSED;
		}
		if (rc == LIBSSH2_ERROR_CHANNEL_CLOSED) break;
		if (rc > 0) {
			con.append(buffer, rc);
			allrd += rc;
			if (mode_delay) continue;
			co_return (int)allrd;
		}
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			if (mode_eow || !eow)
			{
				int ww = co_await wait_socket(eow);
				if (ww > 0) continue;
				if (ww < 0) co_return ww;
			}
			else if (mode_delay)
			{
				int64_t eow2 = GetTickCount64() + delay;
				int ww = co_await wait_socket(&eow2);
				if (ww > 0) continue;
				if (allrd > 0) co_return (int)allrd;
				if (ww < 0) co_return ww;
			}
		}
		break;
	}
	co_return (int) rc;
}

future<int> CSSH2::init_conection()
{
	int rc = 0;
	tmp_sock_t sock(co_await coio::connect(m_host.hostname.c_str(), m_host.port, 15000));
	if (sock.sock < 0) {
		co_return -1;
	}

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
			Log::error("Failed to open channel");
			co_return -1;
		}

		while ((rc = libssh2_channel_request_pty(channel, "xterm")) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
		if (rc)
		{
			Log::error("Failed to request PTY");
			libssh2_channel_free(channel);
			co_return -1;
		}

		while ((rc = libssh2_channel_shell(channel)) == LIBSSH2_ERROR_EAGAIN)
			co_await wait_socket(&eow);
		if (rc) {
			Log::error("Failed to open shell");
			libssh2_channel_free(channel);
			co_return -1;
		}
		m_channel = channel;
		m_bShell = true;
	}

	string content;
	int64_t eow = -200;
	if (co_await coio::io_read(m_sock, 600) & CCoContainer2::user::UF_READABLE)
	{
		co_await ssh_read(content, &eow, 0);
		fwrite(content.data(), 1, content.length(), stdout);
		fflush(stdout);
		content.clear();
	}

	if (!cmd.empty())
	{
		co_await ssh_write(cmd.data(), cmd.length());
	}
	co_return 0;
}

future<int> CSSH2::io_loop()
{
	int ssh_alive = 1;
	int ss2console_running = 1;
	// start ssh->console fiber.
	go_func([&]()->future_free {
		auto q = this;
		string con;
		for (;;)
		{
			DWORD tick0 = GetTickCount();
			coio::io_on(&ssh_alive, 1);
			int code = co_await q->ssh_read(con, 0, false);
			DWORD tdiff  = GetTickCount() - tick0;
			if (code < 0 && code != LIBSSH2_ERROR_EAGAIN)
				break;
			if (!ssh_alive)
				break;
			fwrite(con.data(), 1, con.length(), stdout);
			fflush(stdout);
			con.clear();
		}
		ssh_alive = 0;
		coio::notify_change(&ssh_alive);
		ss2console_running = 0;
		coio::notify_change(&ss2console_running);
		co_return;
	});

	// set console non block, noecho
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	bool isConsole = false;
	coio::add_os_handle(hStdin);
	// test hStdin is console.
	if (GetFileType(hStdin) == FILE_TYPE_CHAR) {
		DWORD mode;
		GetConsoleMode(hStdin, &mode);
		SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));
		isConsole = true;
	}
	for (;;)
	{
		string s;
		coio::io_on(&ssh_alive, 1);
		if (isConsole)
		{
			co_await coio::io_read((fd_t)hStdin, INFINITE);
			s = read_console((fd_t)hStdin);
		}
		else
		{
			ssize_t r = co_await coio::read((fd_t)hStdin, s, INFINITE);
			if (r < 0 && GetLastError() == ERROR_BROKEN_PIPE)
			{
				// co_await ssh_write("\n", 1);
				while (libssh2_channel_send_eof(m_channel) == LIBSSH2_ERROR_EAGAIN)
					co_await wait_socket(0);
				Log::verbose(LOG_WITH_META "sent EOF. set ssh_alive to false");
				ssh_alive = false;
				int ac = coio::notify_change(&ssh_alive);
				Log::verbose(LOG_WITH_META "set ssh_alive false activated %d coroutines", ac);
				break;
			}
		}
		if (!ssh_alive) break;
		if (s.empty()) continue;
		hack_command(s);
		int code = co_await ssh_write(s.data(), s.length());
		(void)code;
	}
	if (ss2console_running) {
		Log::verbose("wait ss2console ends...");
		co_await coio::change(&ss2console_running, 1, INFINITE);
		Log::verbose("wait ss2console ends...DONE");
	}
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
	co_await ssh_read(content, &eow, 0);
	printf("%s\n", content.c_str());
	co_await ssh_read(content, &eow, 1);
	printf("== %s\n", content.c_str());
	co_return 0;
}

future<int> CSSH2::bye() {
	if (m_channel) {
		int64_t eow = GetTickCount64() + 3000;
		if (m_bShell)
			co_await ssh_write("\003\004", 2);
		while (libssh2_channel_send_eof(m_channel) == LIBSSH2_ERROR_EAGAIN && co_await wait_socket(&eow) > 0);
		libssh2_session_set_timeout(m_session, 3000);
		while (libssh2_channel_wait_eof(m_channel) == LIBSSH2_ERROR_EAGAIN && co_await wait_socket(&eow) > 0);
		libssh2_channel_wait_closed(m_channel);
		libssh2_channel_free(m_channel);
		m_channel = 0;
	}
	co_return 0;
}
