/*
 * @file Global.hpp
 * @brief Global definitions, structs, and etc..
 */

#pragma once

#include "Include.hpp"

constexpr auto DOTTEXT_SECTION = ".text\x00\x00\x00";

namespace gl {

	// It is not commonly changed (unless kernel changes MmAccessFault's prototype)
	// So I'll keep that. If issues are present, I'll use LDE for this.
	const size_t MmAccessFaultInstSize = 15;

	namespace Pat {

		const UCHAR CcBcbProfilerPat[] = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00, 0x48, 0x89, 0x74, 0x24, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x8B, 0xF2, 0xE8 };
		const char CcBcbProfilerMask[] = "xxxx?xxxx?xxxx?xxxxxxxxxxxx?xxxx";
		const auto CcBcbProfilerSec = DOTTEXT_SECTION;

	}

	namespace Offsets {

		// Function Offsets.
		const size_t KiWaitAlwaysOff = 0xFC6260;
		const size_t KiWaitNeverOff = 0xFC5F80;
		const size_t KeGetCurrentPrcbOff = 0x442dd0;
		const size_t CcBcbProfilerOff = 0x50AEF0;
		const size_t CcBcbProfiler2Off = 0x6F66a0;
		const size_t MaxDataSizeOff = 0xFC5A48;
		const size_t KiSwInterruptDispatchOff = 0x50BB00;
		const size_t KiMcaDeferredRecoveryServiceOff = 0x6af430;
		const size_t MiVisibleStateOff = 0xFC44C0;
		const size_t MmPteBaseOff = 0xFC4478;
		const size_t KeDelayExecutionTheadOff = 0x3564c0;
		const size_t KeWaitForMultipleObjectsOff = 0x357fa0;
		const size_t KeWaitForSingleObjectOff = 0x290900;
		const size_t MmAccessFaultOff = 0x2afd50;
		const size_t KiPageFaultOff = 0x6b3440;
		const size_t KiBalanceSetManagerDeferredRoutineOff = 0x499c80;
		const size_t KiBalanceSetManagerPeriodicDpcOff = 0xF21660;

		// KiPageFault->MmAccessFault
		const size_t FaultingAddressOff = 0x386 + 0x5;
	}

	namespace RtVar {

		extern uintptr_t KernelBase;
		extern size_t KernelSize;

		extern NTSTATUS(*ZwQuerySystemInformationPtr)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

		extern ULONG64* KiWaitAlwaysPtr;
		extern ULONG64* KiWaitNeverPtr;
		extern void* (*KeGetCurrentPrcbPtr)();
		extern void* CcBcbProfilerPtr;
		extern void* CcBcbProfiler2Ptr;
		extern void* MaxDataSizePtr;
		extern void* KiSwInterruptDispatchPtr;
		extern void* KiMcaDeferredRecoveryServicePtr;
		extern void** MiVisibleStatePtr;
		extern void* KeDelayExecutionThreadPtr;
		extern void* KeWaitForMultipleObjectsPtr;
		extern void* KeWaitForSingleObjectPtr;
		extern NTSTATUS(NTAPI* MmAccessFaultPtr)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID);
		extern void* KiPageFaultPtr;
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