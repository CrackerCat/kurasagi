/*
 * @file Global.cpp
 * @brief Implementation of Global.hpp
 */

#include "Global.hpp"
#include "Log.hpp"
#include "Util/Memory.hpp"

uintptr_t gl::RtVar::KernelBase = 0;
size_t gl::RtVar::KernelSize = 0;

NTSTATUS(*gl::RtVar::ZwQuerySystemInformationPtr)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) = NULL;

ULONG64* gl::RtVar::KiWaitAlwaysPtr = NULL;
ULONG64* gl::RtVar::KiWaitNeverPtr = NULL;
void* (*gl::RtVar::KeGetCurrentPrcbPtr)() = NULL;
void* gl::RtVar::CcBcbProfilerPtr = NULL;
void* gl::RtVar::CcBcbProfiler2Ptr = NULL;
void* gl::RtVar::MaxDataSizePtr = NULL;
void* gl::RtVar::KiSwInterruptDispatchPtr = NULL;
void* gl::RtVar::KiMcaDeferredRecoveryServicePtr = NULL;
void** gl::RtVar::MiVisibleStatePtr = NULL;
void* gl::RtVar::KeDelayExecutionThreadPtr = NULL;
void* gl::RtVar::KeWaitForMultipleObjectsPtr = NULL;
void* gl::RtVar::KeWaitForSingleObjectPtr = NULL;
NTSTATUS(NTAPI* gl::RtVar::MmAccessFaultPtr)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID) = NULL;
void* gl::RtVar::KiPageFaultPtr = NULL;
void* gl::RtVar::KiBalanceSetManagerDeferredRoutinePtr = NULL;
KDPC* gl::RtVar::KiBalanceSetManagerPeriodicDpcPtr = NULL;

uintptr_t gl::RtVar::Pte::MmPdeBase = 0;
uintptr_t gl::RtVar::Pte::MmPdpteBase = 0;
uintptr_t gl::RtVar::Pte::MmPteBase = 0;
uintptr_t gl::RtVar::Pte::MmPml4eBase = 0;

uintptr_t gl::RtVar::Self::SelfBase = NULL;
size_t gl::RtVar::Self::SelfSize = 0;

BOOLEAN gl::RtVar::InitializeRuntimeVariables() {

	// Stage 1
	UNICODE_STRING zwQueryString = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	ZwQuerySystemInformationPtr = (NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))MmGetSystemRoutineAddress(&zwQueryString);

	// Stage 2
	if (!GetKernelBaseNSize(&KernelBase, &KernelSize)) {
		LogError("InitializeRuntimeVariables: Couldn't get kernel base and size");
		return FALSE;
	}

	LogVerbose("Kernel Base: %llx, Kernel Size: %llx", KernelBase, KernelSize);

	// Stage 3
	KiWaitAlwaysPtr = (ULONG64*)(KernelBase + gl::Offsets::KiWaitAlwaysOff);
	KiWaitNeverPtr = (ULONG64*)(KernelBase + gl::Offsets::KiWaitNeverOff);
	KeGetCurrentPrcbPtr = (void* (*)())(KernelBase + gl::Offsets::KeGetCurrentPrcbOff);
	CcBcbProfilerPtr = (void*)(KernelBase + gl::Offsets::CcBcbProfilerOff);
	CcBcbProfiler2Ptr = (void*)(KernelBase + gl::Offsets::CcBcbProfiler2Off);
	KiSwInterruptDispatchPtr = (void*)(KernelBase + gl::Offsets::KiSwInterruptDispatchOff);
	MaxDataSizePtr = (void*)(KernelBase + gl::Offsets::MaxDataSizeOff);
	KiMcaDeferredRecoveryServicePtr = (void*)(KernelBase + gl::Offsets::KiMcaDeferredRecoveryServiceOff);
	MiVisibleStatePtr = (void**)(KernelBase + gl::Offsets::MiVisibleStateOff);
	KeDelayExecutionThreadPtr = (void*)(KernelBase + gl::Offsets::KeDelayExecutionTheadOff);
	KeWaitForSingleObjectPtr = (void*)(KernelBase + gl::Offsets::KeWaitForSingleObjectOff);
	KeWaitForMultipleObjectsPtr = (void*)(KernelBase + gl::Offsets::KeWaitForMultipleObjectsOff);
	MmAccessFaultPtr = (NTSTATUS(NTAPI*)(_In_ ULONG, _In_ PVOID, _In_ KPROCESSOR_MODE, _In_ PVOID))(KernelBase + gl::Offsets::MmAccessFaultOff);
	KiPageFaultPtr = (void*)(KernelBase + gl::Offsets::KiPageFaultOff);
	KiBalanceSetManagerPeriodicDpcPtr = (KDPC*)(KernelBase + gl::Offsets::KiBalanceSetManagerPeriodicDpcOff);
	KiBalanceSetManagerDeferredRoutinePtr = (void*)(KernelBase + gl::Offsets::KiBalanceSetManagerDeferredRoutineOff);

	Pte::MmPteBase = *(uintptr_t*)(KernelBase + gl::Offsets::MmPteBaseOff);

	size_t selfRefIndex = (Pte::MmPteBase >> 39) & 0x1FF;
	uintptr_t base = Pte::MmPteBase;

	base |= (selfRefIndex << 30);
	Pte::MmPdeBase = base;
	base |= (selfRefIndex << 21);
	Pte::MmPdpteBase = base;
	base |= (selfRefIndex << 12);
	Pte::MmPml4eBase = base;
	
	Self::SelfBase = (uintptr_t)&__ImageBase;
	Self::SelfSize = (uintptr_t)&__end - Self::SelfBase;

	uintptr_t res = 0;
	if (!PatternSearchNtKernelSection(Pat::CcBcbProfilerSec, Pat::CcBcbProfilerPat, Pat::CcBcbProfilerMask, &res)) {
		LogError("Couldn't find NT Kernel Section");
		return FALSE;
	}

	if ((uintptr_t)CcBcbProfilerPtr != res) {
		LogError("Fuck");
		return FALSE;
	}

	return TRUE;
}