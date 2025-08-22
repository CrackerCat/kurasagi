/*
 * @file Memory.cpp
 * @brief Implementation for Memory.hpp
 */

#include "Memory.hpp"
#include "../Log.hpp"
#include "../Global.hpp"

BOOLEAN WriteOnReadOnlyMemory(PVOID src, PVOID dst, size_t size) {

	PMDL mdl = NULL;

	if (size == 0) return TRUE;
	mdl = IoAllocateMdl(dst, (ULONG)size, FALSE, FALSE, NULL);

	if (mdl == NULL) {
		LogError("WriteOnReadOnlyMemory: Mdl allocation failed");
		return FALSE;
	}

	PVOID mapped = NULL;
	BOOLEAN success = FALSE;

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		if (mapped == NULL) {
			LogError("WriteOnReadOnlyMemory: MmMapLockedPagesSpecifyCache failed");
			__leave;
		}

		MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
		RtlCopyMemory(mapped, src, size);

		success = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		LogError("WriteOnReadOnlyMemory: Something went wrong, error code: 0x%X", GetExceptionCode());
		success = FALSE;
	}

	if (mapped != NULL) {
		MmUnmapLockedPages(mapped, mdl);
	}

	if (mdl != NULL) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}

	return success;
}


BOOLEAN IsCanonicalAddress(PVOID address) {
	UINT64 bit47 = ((UINT64)address >> 47) & 1;
	if (bit47 * 0xFFFF != ((UINT64)address >> 48)) {
		LogVerbose("IsCanonicalAddress: address %p is not canonical address!", address);
		return FALSE;
	}
	return TRUE;
}

UCHAR GetPml4eVaType(size_t index) {
	if (index < 256 || index >= 512) {
		return 0xFF;
	}
	return ((PMI_VISIBLE_STATE_STUB)*gl::RtVar::MiVisibleStatePtr)->SystemVaType[index - 256];
}

UINT64* GetPageTableEntryPointer(PVOID v, size_t level) {
	if (level == 0 || level > 4) {
		LogError("GetPageTableEntryPointer: Level is invalid!");
		return NULL;
	}

	UINT64* ptePointer = NULL;

	if (level == 1) { // Pt
		ptePointer = (UINT64*)(gl::RtVar::Pte::MmPteBase + (((ULONG64)v >> 9) & 0x7F'FFFF'FFF8));
	}
	else if (level == 2) { // Pd
		ptePointer = (UINT64*)(gl::RtVar::Pte::MmPdeBase + (((ULONG64)v >> 18) & 0x3FFF'FFF8));
	}
	else if (level == 3) { // Pdpt
		ptePointer = (UINT64*)(gl::RtVar::Pte::MmPdpteBase + (((ULONG64)v >> 27) & 0x1F'FFF8));
	}
	else { // level == 4, Pml4
		ptePointer = (UINT64*)gl::RtVar::Pte::MmPml4eBase + (((ULONG64)v >> 39) & 0x1FF);
	}
	
	return ptePointer;
}

UINT64* GetLastPageTableEntryPointer(PVOID v) {

	UINT64* pte = NULL;
	for (size_t level = 4; level > 0; level--) {
		pte = GetPageTableEntryPointer(v, level);
		if (*pte & 1)
			break;
		else
			pte = NULL;
	}
	return pte;
}

PVOID MakeCanonicalAddress(PVOID address) {

	uintptr_t trimmedAddress = ((uintptr_t)address << 16) >> 16;
	
	if ((trimmedAddress >> 47) & 0x1) {
		trimmedAddress |= 0xFFFF'0000'0000'0000;
	}

	return (PVOID)trimmedAddress;
}
 
size_t GetPml4Index(PVOID address) {
	return ((uintptr_t)address >> 39) & 0x1ff;
}

BOOLEAN IsValidAddress(PVOID address) {
	if (!IsCanonicalAddress(address)) return FALSE;
	if (GetLastPageTableEntryPointer(address)) return TRUE;
	else return FALSE;
}

BOOLEAN Hook::HookTrampoline(PVOID origFunction, PVOID hookFunction, PVOID gateway, size_t len) {

	UCHAR detourTemplate[] = {
		0xFF, 0x25, 0, 0, 0, 0
	};

	if (len < sizeof(detourTemplate) + 8) {
		LogError("HookTrampoline: length is invalid, should be greater than %llu", sizeof(detourTemplate) + 8);
		return FALSE;
	}

	if (!WriteOnReadOnlyMemory(origFunction, gateway, len)) {
		return FALSE;
	}

	if (!WriteOnReadOnlyMemory(detourTemplate, (PVOID)((uintptr_t)gateway + len), sizeof(detourTemplate))) {
		return FALSE;
	}

	uintptr_t returnAddress = (uintptr_t)origFunction + len;
	if (!WriteOnReadOnlyMemory(&returnAddress, (PVOID)((uintptr_t)gateway + len + sizeof(detourTemplate)), 8)) {
		return FALSE;
	}

	if (!WriteOnReadOnlyMemory(detourTemplate, origFunction, sizeof(detourTemplate))) {
		return FALSE;
	}
	
	uintptr_t detourAddress = (uintptr_t)hookFunction;
	if (!WriteOnReadOnlyMemory(&detourAddress, (PVOID)((uintptr_t)origFunction + sizeof(detourTemplate)), 8)) {
		return FALSE;
	}

	// So, the gateway is like this:
	// .. (original code) .. | jmp [rip+0x00] | Orig.

	// And the original function is like this:
	// jmp [rip+0x00] | Hook
	
	return TRUE;
}

NTSTATUS GetModuleInformation(const char* szModuleName, PSYSTEM_MODULE_ENTRY outTargetModule) {
	ULONG infoLen = 0;
	auto status = gl::RtVar::ZwQuerySystemInformationPtr(SystemModuleInformation, &infoLen, 0, &infoLen);
	// It is okay to do this way
	// It should return 0xC0000004, but it is fine - it fills infoLen

	PSYSTEM_MODULE_INFORMATION pMod = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, infoLen, KURASAGI_POOL_TAG);
	if (!pMod) {
		LogError("GetModuleInformation: Allocation Failed");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = gl::RtVar::ZwQuerySystemInformationPtr(SystemModuleInformation, pMod, infoLen, &infoLen);
	if (!NT_SUCCESS(status)) {
		LogError("GetModuleInformation: Second ZwQuery Failed: %x", status);
		return status;
	}

	PSYSTEM_MODULE_ENTRY pModEntry = pMod->Module;
	for (ULONG i = 0; i < pMod->Count; i++) {
		if (!_stricmp((const char*)pModEntry[i].FullPathName, szModuleName))
		{
			*outTargetModule = pModEntry[i];
			return STATUS_SUCCESS;
		}
	}

	LogError("GetModuleInformation: Not Found");
	return STATUS_NOT_FOUND;
}

BOOLEAN GetKernelBaseNSize(uintptr_t* outBase, size_t* outSize) {
	SYSTEM_MODULE_ENTRY entry = { 0 };
	auto status = GetModuleInformation("\\SystemRoot\\system32\\ntoskrnl.exe", &entry);

	if (!NT_SUCCESS(status)) {
		LogError("GetKernelBaseNSize: Not Found");
		return FALSE;
	}

	*outBase = (uintptr_t)entry.ImageBase;
	*outSize = entry.ImageSize;

	return TRUE;
}

BOOLEAN PatternSearchRange(unsigned char* start, unsigned char* end, const UCHAR* pattern, const char* mask, uintptr_t* result) {

	if (!start || !end || !pattern || !mask || !result) {
		LogError("PatternSearchRange: Invalid Parameter");
		return FALSE;
	}

	size_t m = strlen(mask);

	for (auto ptr = start; ptr + m <= end; ptr++) {
		size_t j = 0;
		for (; j < m; j++) {
			if (mask[j] == 'x' && ptr[j] != pattern[j]) break;
		}
		if (j == m) {
			*result = (uintptr_t)ptr;
			return TRUE;
		}
	}

	return FALSE;
}