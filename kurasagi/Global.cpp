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
void* gl::RtVar::CcBcbProfilerPtr = NULL;
void* gl::RtVar::CcBcbProfiler2Ptr = NULL;
void* gl::RtVar::MaxDataSizePtr = NULL;
void* gl::RtVar::KiSwInterruptDispatchPtr = NULL;
void* gl::RtVar::KiMcaDeferredRecoveryServicePtr = NULL;
void** gl::RtVar::MiVisibleStatePtr = NULL;
void* gl::RtVar::MmAccessFaultPtr = NULL;
void* gl::RtVar::FaultingAddrPtr = NULL;
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

	BOOLEAN res = TRUE;
	res &= PatternSearchNtKernelSection(Pat::CcBcbProfilerSec, Pat::CcBcbProfilerPat, Pat::CcBcbProfilerMask, (uintptr_t*)&CcBcbProfilerPtr);
	res &= PatternSearchNtKernelSection(Pat::CcBcbProfiler2Sec, Pat::CcBcbProfiler2Pat, Pat::CcBcbProfiler2Mask, (uintptr_t*)&CcBcbProfiler2Ptr);
	res &= PatternSearchNtKernelSection(Pat::KiMcaDeferredRecoveryServiceSec, Pat::KiMcaDeferredRecoveryServicePat, Pat::KiMcaDeferredRecoveryServiceMask, (uintptr_t*)&KiMcaDeferredRecoveryServicePtr);
	res &= PatternSearchNtKernelSection(Pat::KiBalanceSetManagerDeferredRoutineSec, Pat::KiBalanceSetManagerDeferredRoutinePat, Pat::KiBalanceSetManagerDeferredRoutineMask, (uintptr_t*)&KiBalanceSetManagerDeferredRoutinePtr);
	res &= PatternSearchNtKernelSection(Pat::FaultingAddressSec, Pat::FaultingAddressPat, Pat::FaultingAddressMask, (uintptr_t*)&FaultingAddrPtr);
	res &= PatternSearchNtKernelSection(Pat::MmAccessFaultSec, Pat::MmAccessFaultPat, Pat::MmAccessFaultMask, (uintptr_t*)&MmAccessFaultPtr);
	res &= PatternSearchNtKernelSection(Pat::KiSwInterruptDispatchSec, Pat::KiSwInterruptDispatchPat, Pat::KiSwInterruptDispatchMask, (uintptr_t*)&KiSwInterruptDispatchPtr);

	KiWaitAlwaysPtr = (ULONG64*)(KernelBase + gl::Offsets::KiWaitAlwaysOff);
	KiWaitNeverPtr = (ULONG64*)(KernelBase + gl::Offsets::KiWaitNeverOff);
	MaxDataSizePtr = (void*)(KernelBase + gl::Offsets::MaxDataSizeOff);
	MiVisibleStatePtr = (void**)(KernelBase + gl::Offsets::MiVisibleStateOff);
	KiBalanceSetManagerPeriodicDpcPtr = (KDPC*)(KernelBase + gl::Offsets::KiBalanceSetManagerPeriodicDpcOff);

	Pte::MmPteBase = *(uintptr_t*)(KernelBase + gl::Offsets::MmPteBaseOff);

	if (!res) {
		LogError("InitializeRuntimeVariables: Couldn't scan signatures...");
		return FALSE;
	}

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

	return TRUE;
}