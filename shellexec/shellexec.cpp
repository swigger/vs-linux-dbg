#include "stdafx.h"
#include <atlbase.h>
#include <atlcom.h>
#include "util.h"
#include "ssh2.h"
#include "sync/coco2.h"
#include "base/log.h"
// #include "base/utilhex.h"
#import <msxml6.dll> raw_interfaces_only

namespace {
	bool get_string(IXMLDOMNode* node, LPCWSTR subnode, std::string& value)
	{
		CComPtr<IXMLDOMNode> pSubNode;
		HRESULT hr = node->selectSingleNode(CComBSTR(subnode), &pSubNode);
		if (FAILED(hr) || !pSubNode) return false;
		CComBSTR otext;
		hr = pSubNode->get_text(&otext);
		if (FAILED(hr)) return false;

		value.resize(otext.Length() * 3 + 10);
		int len = WideCharToMultiByte(CP_UTF8, 0, otext, otext.Length(), &value[0], (int)value.size(), nullptr, nullptr);
		value.resize(len);
		return true;
	}
	bool get_int(IXMLDOMNode* node, LPCWSTR subnode, int64_t& value)
	{
		CComPtr<IXMLDOMNode> pSubNode;
		HRESULT hr = node->selectSingleNode(CComBSTR(subnode), &pSubNode);
		if (FAILED(hr) || !pSubNode) return false;
		CComBSTR otext;
		hr = pSubNode->get_text(&otext);
		if (FAILED(hr)) return false;
		value = wcstoll(otext, 0, 0);
		return true;
	}
	bool get_int(IXMLDOMNode* node, LPCWSTR subnode, int& value)
	{
		int64_t val0 = 0;
		bool rt = get_int(node, subnode, val0);
		value = (int)val0;
		return rt;
	}
	bool get_attr(IXMLDOMNode* node, LPCWSTR key, string& val) {
		CComPtr<IXMLDOMNamedNodeMap> pAttributes;
		HRESULT hr = node->get_attributes(&pAttributes);
		if (FAILED(hr)) return false;
		CComPtr<IXMLDOMNode> pIdAttr;
		hr = pAttributes->getNamedItem(CComBSTR(key), &pIdAttr);
		if (FAILED(hr) || !pIdAttr) return false;
		CComBSTR text;
		hr = pIdAttr->get_text(&text);
		if (FAILED(hr)) return false;
		val.resize(text.Length() * 3 + 10);
		int len = WideCharToMultiByte(CP_UTF8, 0, text, text.Length(), &val[0], (int)val.size(), nullptr, nullptr);
		val.resize(len);
		return true;
	}
	bool get_attr(IXMLDOMNode* node, LPCWSTR key, int64_t& val) {
		CComPtr<IXMLDOMNamedNodeMap> pAttributes;
		HRESULT hr = node->get_attributes(&pAttributes);
		if (FAILED(hr)) return false;
		CComPtr<IXMLDOMNode> pIdAttr;
		hr = pAttributes->getNamedItem(CComBSTR(key), &pIdAttr);
		if (FAILED(hr) || !pIdAttr) return false;
		CComBSTR text;
		hr = pIdAttr->get_text(&text);
		if (FAILED(hr)) return false;
		val = wcstoll(text, 0, 0);
		return true;
	}
}

struct Store {
	std::map<int64_t, CSSH2::Host> entries;
};

static bool parseXML(LPCWSTR fn, Store& store)
{
	HRESULT hr;
	CComPtr<IXMLDOMDocument> pDoc;
	hr = CoCreateInstance(__uuidof(MSXML2::DOMDocument60), nullptr, CLSCTX_INPROC_SERVER, __uuidof(IXMLDOMDocument), (void**)&pDoc);
	if (FAILED(hr))	return false;

	VARIANT_BOOL varStatus = 0;
	hr = pDoc->load(CComVariant(fn), &varStatus);
	if (FAILED(hr))	return false;

	CComPtr<IXMLDOMNodeList> pEntries;
	hr = pDoc->selectNodes(CComBSTR(L"/store/entries/entry"), &pEntries);
	if (FAILED(hr))	return false;

	long length;
	pEntries->get_length(&length);

	for (long i = 0; i < length; ++i) {
		CComPtr<IXMLDOMNode> entry;
		hr = pEntries->get_item(i, &entry);
		if (FAILED(hr))	continue;
		CSSH2::Host entry1;
		int64_t id;
		util::RecordResult rr;
		rr << get_attr(entry, L"id", id);
		rr << get_string(entry, L"hostname", entry1.hostname);
		rr << get_int(entry, L"port", entry1.port);
		rr << get_string(entry, L"fingerprint", entry1.fingerprint);

		CComPtr<IXMLDOMNode> auth;
		entry->selectSingleNode(CComBSTR(L"credentials"), &auth);
		if (!auth) continue;
		rr << get_string(auth, L"username", entry1.username);
		rr << get_string(auth, L"authenticationMethod", entry1.authenticationMethod);
		get_string(auth, L"privateFileName", entry1.privateFileName);
		get_string(auth, L"passphrase", entry1.passphrase);
		if (rr) store.entries[id] = entry1;
	}
	return true;
}

class CSSH2xx : public CSSH2
{
public:
	CSSH2xx(const Host& host) : CSSH2(host) {}
	bool m_isGdb = false;
protected:
	void hack_command(string& cmd) override
	{
		if (m_isGdb) {
			if (cmd == "logout\n" || cmd == "logout\r\n")
			{
				cmd = "quit\n" + cmd;
			}
		}
	}
};

future_free run_ssh2(CSSH2::Host & host, crefstr cmd, int * rr)
{
	CSSH2xx ssh(host);
	ssh.m_isGdb = cmd.find("gdb") != string::npos;
	int rcode=0;
	if (co_await ssh.init_conection() < 0) {
		fprintf(stderr, "failed to connect to %s:%d\n", host.hostname.c_str(), host.port);
		rcode = 1;
	}
	else
	{
		rcode = co_await ssh.run_shell(cmd);
		co_await ssh.io_loop();
		co_await ssh.bye();
	}
	*rr = rcode;
	CCoContainer2::current()->mark_stop();
	co_return;
}

int main1(int argc, char** argv)
{
	int64_t conid = -1;
	int sync_pid = -1;
	string cmd;
	Log::verbose_value = 2;
	Log::open("ssh2.log");
	Log::verbose(LOG_WITH_META "===========io:%#zx,%#zx,%#zx CommandLine: %s\n",
		(intptr_t) GetStdHandle(STD_INPUT_HANDLE),
		(intptr_t) GetStdHandle(STD_OUTPUT_HANDLE),
		(intptr_t) GetStdHandle(STD_ERROR_HANDLE),
		GetCommandLineA());

	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "/c") == 0) {
			for (++i; i < argc; ++i) {
				cmd += argv[i];
				if (i+1 < argc) cmd += ' ';
			}
		}
		else if (strcmp(argv[i], "/p") == 0) {
			sync_pid = atoi(argv[++i]);
		} else if (strcmp(argv[i], "/s") == 0) {
			conid = atoll(argv[++i]);
		}
		else if (i == 1) {
			// ignore first arg, might be path/to/shellexec.exe
		}
		else {
			fprintf(stderr, "unknown option %s\n", argv[i]);
			return 1;
		}
	}
	if (conid < 0)
	{
		fprintf(stderr, "missing connection id\n");
		return 1;
	}

	Store store;
	bool b = parseXML(LR"(C:\Users\xungeng\AppData\Local\Microsoft\Linux\User Data\3.0\store.xml)", store);
	if (!b) {
		fprintf(stderr, "failed to load store.xml\n");
		return 1;
	}
	auto it = store.entries.find(conid);
	if (it == store.entries.end()) {
		fprintf(stderr, "connection id %lld not found\n", conid);
		return 1;
	}
	if (!cmd.empty()) cmd += "\n";

	auto& entry = it->second;
	CCoContainer2 cont(1);
	int rr = 0;
	cont.run([&](){
		run_ssh2(entry, cmd, &rr);
	});
	Log::verbose(LOG_WITH_META "run_ssh2 DONE, return %d\n", rr);
	return rr;
}

int main(int argc, char** argv)
{
	WSADATA wsd;
	(void)WSAStartup(MAKEWORD(2, 2), &wsd);
	(void)CoInitialize(nullptr);
	// MessageBox(NULL, L"dbgme", L"dbgme", MB_SERVICE_NOTIFICATION|MB_ICONASTERISK);
	int rt = main1(argc, argv);
	CoUninitialize();
	WSACleanup();
	return rt;
}


#ifdef _WIN32
#ifndef STATUS_ALERTED
#define STATUS_ALERTED 0x101
#endif

extern "C" NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

static int conv_ntstatus(NTSTATUS nt)
{
	if (nt == STATUS_ALERTED || nt == STATUS_USER_APC)
	{
		errno = EINTR;
		return -1;
	}
	return 0;
}

extern "C" int usleep(uint32_t timeout)
{
	LARGE_INTEGER li;
	li.QuadPart = -(int64_t)timeout * 10;
	NTSTATUS nt = NtDelayExecution(FALSE, (timeout == -1) ? 0 : &li);
	return conv_ntstatus(nt);
}

extern "C" int gettid(void) {
	return (int)GetCurrentThreadId();
}
#endif
