#include "stdafx.h"
#include "..\NtVer\nt_ver.h"
_NT_BEGIN

#include "qpm.h"
//#include "../tkn/tkn.h"
#include "alog.h"

ULONG Init(_Inout_ PSYSTEM_PROCESS_INFORMATION pspi)
{
	ULONG NextEntryOffset = 0, n = 0;
	do 
	{
		(PBYTE&)pspi += NextEntryOffset;
		pspi->PageDirectoryBase = 0;
		pspi->SpareLi1.QuadPart = 0;
		pspi->SpareLi2.QuadPart = 0;
		pspi->SpareLi3.QuadPart = 0;

		n++;

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return n;
}

void DumpTree(_In_ ALog& log, _In_ PCSTR prefix, _In_ PSYSTEM_PROCESS_INFORMATION pspi, _In_ HANDLE UniqueProcessId)
{
	if (*prefix == -1)
	{
		return ;
	}

	log("%s%08x %wZ\r\n", prefix, UniqueProcessId, pspi->ImageName);
	pspi->SpareLi3.LowPart = 1;

	while (ULONG NextEntryOffset = pspi->NextEntryOffset)
	{
		(PBYTE&)pspi += NextEntryOffset;

		if (pspi->InheritedFromUniqueProcessId == UniqueProcessId)
		{
			DumpTree(log, prefix - 1, pspi, pspi->UniqueProcessId);
		}
	}
}

void DumpTree(_In_ ALog& log, _In_ PCSTR prefix, _In_ PSYSTEM_PROCESS_INFORMATION pspi)
{
	PSYSTEM_PROCESS_INFORMATION _pspi = pspi;

	ULONG NextEntryOffset = 0;
	do 
	{
		(PBYTE&)pspi += NextEntryOffset;

		if (HANDLE UniqueProcessId = pspi->UniqueProcessId)
		{
			if (!pspi->SpareLi3.LowPart)
			{
				_pspi->NextEntryOffset = RtlPointerToOffset(_pspi, pspi);
				DumpTree(log, prefix, _pspi, pspi->InheritedFromUniqueProcessId);
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);
}

void DumpTree(_In_ ALog& log, _In_ PSYSTEM_PROCESS_INFORMATION pspi)
{
	char prefix[64];
	memset(prefix, '\t', _countof(prefix));
	prefix[_countof(prefix) - 1] = 0;
	*prefix = -1;

	ULONG NextEntryOffset = pspi->NextEntryOffset;

	DumpTree(log, prefix + _countof(prefix) - 1, pspi);

	pspi->NextEntryOffset = NextEntryOffset;
}

void Dump(_In_ ALog& log, _In_ PSYSTEM_PROCESS_INFORMATION pspi)
{
	ULONG NextEntryOffset = 0;
	do 
	{
		(PBYTE&)pspi += NextEntryOffset;

		if (pspi->UniqueProcessId)
		{
			union {
				LONG Flags;
				struct {
					ULONG IsProtectedProcess : 1;
					ULONG IsWow64Process : 1;
					ULONG IsProcessDeleting : 1;
					ULONG IsCrossSessionCreate : 1;
					ULONG IsFrozen : 1;
					ULONG IsBackground : 1;
					ULONG IsStronglyNamed : 1;
					ULONG IsSecureProcess : 1;
					ULONG IsSubsystemProcess : 1;
					ULONG SpareBits : 23;
				};
			};

			Flags = get_Flags(pspi);

			CHAR sz[] = ".........";

			static const char sf[] = "PWDCFBNSY";

			ULONG i = _countof(sz) - 1;
			do 
			{
				if (_bittest(&Flags, --i))
				{
					sz[i] = sf[i];
				}
			} while (i);

			log("%08x(%08x) %s %x %3u %6u %8u/%8u %wZ\r\n", 
				pspi->UniqueProcessId, pspi->InheritedFromUniqueProcessId, sz, 
				pspi->SessionId, pspi->NumberOfThreads, pspi->HandleCount,
				pspi->PrivatePageCount >> 10, pspi->WorkingSetSize >> 10,
				pspi->ImageName);
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);
}

void DumpModules(_In_ ALog& log, _In_ PSYSTEM_PROCESS_INFORMATION pspi)
{
	ULONG NextEntryOffset = 0;
	do 
	{
		(PBYTE&)pspi += NextEntryOffset;

		if (pspi->UniqueProcessId)
		{
			PCSTR psz = get_cmdline(pspi);

			log("%08x [%x] %wZ >> %s\r\n", 
				pspi->UniqueProcessId, get_status(pspi), pspi->ImageName, psz ? psz : "");

			ULONG n;
			if (PROCESS_MODULE* ppm = get_modules(pspi, &n))
			{
				do 
				{
					log("\t[%03u] %p %08x %s\r\n", GetLoadCount(ppm), ppm->ImageBase, ppm->ImageSize, ppm->FullPathName);

				} while (ppm++, --n);
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);
}

enum Colum { CID_ORDER, CID_COUNT, CID_BASE, CID_SIZE, CID_NAME };

struct Sort 
{
	int s;
	Colum c;

	static int CompareU(ULONG_PTR a, ULONG_PTR b)
	{
		if (a < b) return -1;
		if (a > b) return +1;
		return 0;
	}

	int Compare(PROCESS_MODULE* p, PROCESS_MODULE* q)
	{
		switch (c)
		{
		case CID_ORDER:
			return CompareU(p->Index, q->Index);
		case CID_COUNT:
			return CompareU(GetLoadCount(p), GetLoadCount(q));
		case CID_BASE:
			return CompareU((ULONG_PTR)p->ImageBase, (ULONG_PTR)q->ImageBase);
		case CID_SIZE:
			return CompareU(p->ImageSize, q->ImageSize);
		case CID_NAME:
			return strcmp(p->FullPathName, q->FullPathName);
		}

		return 0;
	}

	static int __cdecl FuncCompare(void * This, const void * p, const void * q)
	{
		return reinterpret_cast<Sort*>(This)->s * 
			reinterpret_cast<Sort*>(This)->Compare(*(PROCESS_MODULE**)p, *(PROCESS_MODULE**)q);
	}
};

void QueryThread(_In_ ALog& log, _In_ NAMES* Table)
{
	if (PSYSTEM_PROCESS_INFORMATION pspi = Table->BuildListOfProcesses())
	{
		ULONG n = Init(pspi);
		DumpTree(log, pspi);

		static LARGE_INTEGER SectionSize = { MaxThreads << secshift };

		HANDLE hSection;

		if (0 <= NtCreateSection(&hSection, SECTION_ALL_ACCESS, 0, &SectionSize, PAGE_READWRITE, SEC_COMMIT, 0))
		{
			PVOID BaseAddress = 0;
			SIZE_T ViewSize = 0;

			if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_READWRITE))
			{
				Table->QueryLoop(pspi, hSection, BaseAddress);

				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
			}

			NtClose(hSection);
		}

		log("%u Processes, %u(%u) PE, %u Kb\r\n", 
			n, RtlNumberGenericTableElementsAvl(Table), 
			Table->GetModulesCount(), Table->GetMemUsage() >> 10);

		Dump(log, pspi);
		DumpModules(log, pspi);

		if (n = RtlNumberGenericTableElementsAvl(Table))
		{
			if (PVOID buf = Table->malloca(n * sizeof(PVOID)))
			{
				PROCESS_MODULE** pppm = (PROCESS_MODULE**)buf, *ppm;

				Table->FillModules(pppm);

				Sort ctx { -1, CID_COUNT };
				qsort_s(buf, n, sizeof(PVOID), Sort::FuncCompare, &ctx);

				do 
				{
					ppm = *pppm++;

					log("\t[%03u] %p %08x %s\r\n", GetLoadCount(ppm), ppm->ImageBase, ppm->ImageSize, ppm->FullPathName);
				} while (--n);

				Table->freea(buf);
			}
		}
	}
}

#include "types.h"

void PrintTypes(ALog& log)
{
	COBJECT_ALL_TYPES_INFORMATION ati;

	if (0 <= ati.Init())
	{
		if (ULONG n = ati.count())
		{
			log(
				" I  Access       GE        GR        GW        GA        O        mO         H       mH        PT       IA    Name\r\n"
				"==================================================================================================================\r\n");
			const OBJECT_TYPE_INFORMATION* pti = ati;
			do 
			{
				log("%02x %08x { %08x, %08x, %08x, %08x} %08x(%08x) %08x(%08x) %08x %08x %wZ\r\n", 
					pti->TypeIndex, 
					pti->ValidAccessMask,
					pti->GenericMapping.GenericExecute,
					pti->GenericMapping.GenericRead,
					pti->GenericMapping.GenericWrite,
					pti->GenericMapping.GenericAll,
					pti->TotalNumberOfObjects,
					pti->HighWaterNumberOfObjects,
					pti->TotalNumberOfHandles,
					pti->HighWaterNumberOfHandles,
					pti->PoolType,
					pti->InvalidAttributes,
					&pti->TypeName);

			} while (pti++, --n);
		}
	}

	log << "\r\n\r\n";
}

#include "..\inc\initterm.h"

void WINAPI ep(void*)
{
#ifdef _WIN64
	InitWow64();
#endif

	BOOLEAN w;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &w);

	initterm();

	enum { Size = 0x200000 };//2Mb

	ULONG t = GetTickCount();

	{
		NAMES Table;
		if (Table.Create(Size))
		{
			ALog log;
			if (0 <= log.Init(Size))
			{
				log("%04x %08x %u.%u.%u\r\n\r\n", g_nt_ver.Version, g_nt_ver.FullVersion, g_nt_ver.Major, g_nt_ver.Minor, g_nt_ver.Build);

				PrintTypes(log);

				QueryThread(log, &Table);

				log("\r\nquery time = %u ms\r\n", GetTickCount() - t);

				if (ULONG n = log.size())
				{
					HANDLE hFile = CreateFileW(L"$.log", FILE_APPEND_DATA, 0, 0, CREATE_ALWAYS, 0, 0);
					if (hFile != INVALID_HANDLE_VALUE)
					{
						WriteFile(hFile, (PCSTR)log, n, &n, 0);
						NtClose(hFile);
					}
				}
			}
		}
	}

	destroyterm();

	ExitProcess(0);
}

_NT_END