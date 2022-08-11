#include "stdafx.h"

_NT_BEGIN

#include "alog.h"

ULONG ALog::Init(SIZE_T RegionSize)
{
	if (PVOID BaseAddress = LocalAlloc(0, RegionSize))
	{
		_RegionSize = (ULONG)RegionSize, _Ptr = 0, _BaseAddress = BaseAddress;
		*(CHAR*)BaseAddress = 0;
		return NOERROR;
	}
	return GetLastError();
}

ALog::~ALog()
{
	if (_BaseAddress)
	{
		LocalFree(_BaseAddress);
	}
}

ALog& ALog::operator ()(PCSTR format, ...)
{
	va_list args;
	va_start(args, format);

	int len = _vsnprintf_s(_buf(), _cch(), _TRUNCATE, format, args);

	if (0 < len)
	{
		_Ptr += len;
	}

	va_end(args);

	return *this;
}

ALog& ALog::operator << (PCSTR str)
{
	PSTR buf = _buf();
	if (!strcpy_s(buf, _cch(), str))
	{
		_Ptr += (ULONG)strlen(buf);
	}
	return *this;
}

ALog& ALog::operator[](HRESULT dwError)
{
	if (dwError)
	{
		LPCVOID lpSource = 0;
		ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS;

		if (dwError & FACILITY_NT_BIT)
		{
			dwError &= ~FACILITY_NT_BIT;
__nt:
			dwFlags = FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_IGNORE_INSERTS;

			static HMODULE ghnt;
			if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return *this;
			lpSource = ghnt;
		}

		if (ULONG cch = FormatMessageA(dwFlags, lpSource, dwError, 0, _buf(), _cch(), 0))
		{
			_Ptr += cch;
		}
		else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
		{
			goto __nt;
		}
	}

	return *this;
}

_NT_END