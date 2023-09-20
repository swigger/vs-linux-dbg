#include "stdafx.h"
#include "util.h"
#include "ssh2.h"
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
		int len = WideCharToMultiByte(CP_UTF8, 0, otext, otext.Length(), &value[0], value.size(), nullptr, nullptr);
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
		int len = WideCharToMultiByte(CP_UTF8, 0, text, text.Length(), &val[0], val.size(), nullptr, nullptr);
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
	std::map<int64_t, SSH2Host> entries;
};

bool parseXML(LPCWSTR fn, Store& store)
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
		SSH2Host entry1;
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

int main1(int argc, char** argv)
{
	Store store;
	bool b = parseXML(LR"(C:\Users\xungeng\AppData\Local\Microsoft\Linux\User Data\3.0\store.xml)", store);
	if (!b) {
		fprintf(stderr, "failed to load store.xml\n");
		return 1;
	}
	for (auto& [id, entry] : store.entries) {
		printf("%lld %s %d %s %s %s\n", id, entry.hostname.c_str(), entry.port, entry.username.c_str(), entry.authenticationMethod.c_str(), entry.privateFileName.c_str());
	}
	return 0;
}

int main(int argc, char** argv)
{
	WSADATA wsd;
	WSAStartup(MAKEWORD(2, 2), &wsd);
	CoInitialize(nullptr);
	int rt = main1(argc, argv);
	CoUninitialize();
	WSACleanup();
	return rt;
}
