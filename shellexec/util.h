#pragma once

namespace util
{
	struct RecordResult {
		bool m_ok = true;

		void operator<< (bool b) {
			m_ok = m_ok && b;
		}
		void operator<< (HRESULT hr) {
			m_ok = m_ok && SUCCEEDED(hr);
		}
		operator bool() {
			return m_ok;
		}
	};
}
