#pragma once

class ALog
{
	PVOID _BaseAddress;
	ULONG _RegionSize, _Ptr;

public:
	PSTR _buf()
	{
		return (PSTR)_BaseAddress + _Ptr;
	}

	ULONG _cch()
	{
		return _RegionSize - _Ptr;
	}

	ULONG Init(SIZE_T RegionSize);

	~ALog();

	ALog(ALog&&) = delete;
	ALog(ALog&) = delete;
	ALog(): _BaseAddress(0) {  }

	operator PCSTR()
	{
		return (PCSTR)_BaseAddress;
	}

	ULONG size()
	{
		return _Ptr;
	}

	ALog& operator << (PCSTR str);

	ALog& operator ()(PCSTR format, ...);

	ALog& operator[](HRESULT dwError);
};
