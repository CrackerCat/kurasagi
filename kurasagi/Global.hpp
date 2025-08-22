/*
 * @file Global.hpp
 * @brief Global definitions, structs, and etc..
 */

#pragma once

#include "Include.hpp"

constexpr auto DOTTEXT_SECTION = ".text\x00\x00\x00";
constexpr auto PAGE_SECTION = "PAGE\x00\x00\x00\x00";

namespace gl {

	// It is not commonly changed (unless kernel changes MmAccessFault's prototype)
	// So I'll keep that. If issues are present, I'll use LDE for this.
	const size_t MmAccessFaultInstSize = 15;

	namespace Pat {

		// CcBcbProfiler
		const UCHAR CcBcbProfilerPat[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00, 0x48, 0x89, 0x74, 0x24, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x8B, 0xF2, 0xE8 };
		const char  CcBcbProfilerMask[] = "xxxx?xxxx?xxxx?xxxxxxxxxxxx?xxxx";
		const auto  CcBcbProfilerSec = DOTTEXT_SECTION;

		// CcBcbProfiler2
		const UCHAR CcBcbProfiler2Pat[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x8B, 0xF1, 0xE8 };
		const char  CcBcbProfiler2Mask[] = "xxxx?xxxxxxxxxxxxxx?xxxx";
		const auto  CcBcbProfiler2Sec = PAGE_SECTION;

		// KiMcaDeferredRecoveryService
		const UCHAR KiMcaDeferredRecoveryServicePat[] = { 0x33, 0xC0, 0x8B, 0xD8, 0x8B, 0xF8 };
		const char  KiMcaDeferredRecoveryServiceMask[] = "xxxxxx";
		const auto  KiMcaDeferredRecoveryServiceSec = DOTTEXT_SECTION;

		// KiBalanceSetManagerDeferredRoutine
		const UCHAR KiBalanceSetManagerDeferredRoutinePat[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48, 0x89, 0x70, 0x00, 0x48, 0x89, 0x78, 0x00, 0x48, 0x89, 0x50, 0x00, 0x41, 0x56, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xA4, 0x24, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xF1, 0x49, 0x8B, 0xF0, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF9, 0x33, 0xD2, 0x44, 0x8D, 0x42, 0x00, 0x48, 0x8D, 0x88, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xC3, 0x48, 0xC1, 0xF8, 0x00, 0x48, 0xFF, 0xC0, 0x48, 0x83, 0xF8, 0x00, 0x0F, 0x87 };
		const char  KiBalanceSetManagerDeferredRoutineMask[] = "xxxxxx?xxx?xxx?xxx?xxxxx????xxxx????xxxxxxxxxxxxxxxxx?xxx????x????xxxxxx?xxxxxx?xx";
		const auto  KiBalanceSetManagerDeferredRoutineSec = DOTTEXT_SECTION;

		// FaultingAddr
		const UCHAR FaultingAddressPat[] = { 0x85, 0xC0, 0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, 0xF6, 0x85 };
		const char  FaultingAddressMask[] = "xxxx????xx";
		const auto  FaultingAddressSec = DOTTEXT_SECTION;

		// MmAccessFault
		const UCHAR MmAccessFaultPat[] = { 0x40, 0x55, 0x53, 0x56, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };
		const char  MmAccessFaultMask[] = "xxxxxxxxxx";
		const auto  MmAccessFaultSec = DOTTEXT_SECTION;

		// KiSwInterruptDispatch
		const UCHAR KiSwInterruptDispatchPat[] = { 0x48, 0x89, 0x4C, 0x24, 0x00, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x3D };
		const char  KiSwInterruptDispatchMask[] = "xxxx?xxxxxxxxxxxxxxxx?xxx????xxx";
		const auto  KiSwInterruptDispatchSec = DOTTEXT_SECTION;
	}

	namespace Offsets {

		// Function Offsets.
		const size_t KiWaitAlwaysOff = 0xFC6260;
		const size_t KiWaitNeverOff = 0xFC5F80;
		const size_t MaxDataSizeOff = 0xFC5A48;
		const size_t MiVisibleStateOff = 0xFC44C0;
		const size_t MmPteBaseOff = 0xFC4478;
		const size_t KiBalanceSetManagerPeriodicDpcOff = 0xF21660;
	}

	namespace RtVar {

		extern uintptr_t KernelBase;
		extern size_t KernelSize;

		extern NTSTATUS(*ZwQuerySystemInformationPtr)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

		extern ULONG64* KiWaitAlwaysPtr;
		extern ULONG64* KiWaitNeverPtr;
		extern void* CcBcbProfilerPtr;
		extern void* CcBcbProfiler2Ptr;
		extern void* MaxDataSizePtr;
		extern void* KiSwInterruptDispatchPtr;
		extern void* KiMcaDeferredRecoveryServicePtr;
		extern void** MiVisibleStatePtr;
		extern void* MmAccessFaultPtr;
		extern void* FaultingAddrPtr;
		extern void* KiBalanceSetManagerDeferredRoutinePtr;
		extern KDPC* KiBalanceSetManagerPeriodicDpcPtr;

		namespace Pte {
			extern uintptr_t MmPteBase;
			extern uintptr_t MmPdeBase;
			extern uintptr_t MmPdpteBase;
			extern uintptr_t MmPml4eBase;
		}

		namespace Self {
			extern uintptr_t SelfBase;
			extern size_t SelfSize;
		}

		/*
		 * @brief Initialize `RtVar` variables, which is known at runtime.
		 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
		 */
		BOOLEAN InitializeRuntimeVariables();
	}
}

constexpr auto KURASAGI_POOL_TAG = 'Krsg';

extern "C" IMAGE_DOS_HEADER __ImageBase;

#pragma section(".endsec", read)
__declspec(allocate(".endsec")) const char __end = 0;

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define TODO(msg) __pragma(message(__FILE__ "(" STRINGIZE(__LINE__) "): TODO: " msg))