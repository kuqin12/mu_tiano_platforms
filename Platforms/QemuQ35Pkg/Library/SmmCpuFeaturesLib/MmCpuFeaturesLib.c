/** @file
  The CPU specific programming for PiSmmCpuDxeSmm module.

  Copyright (c) 2010 - 2015, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <IndustryStandard/Q35MchIch9.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemEncryptSevLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/SafeIntLib.h>
#include <Library/SmmCpuFeaturesLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/HobLib.h>
#include <Pcd/CpuHotEjectData.h>
#include <PiSmm.h>
#include <Register/Amd/SmramSaveStateMap.h>
#include <Guid/SmmBaseHob.h>

#include <Library/FvLib.h>
#include <Library/HobLib.h>
#include <SeaResponder.h>
#include <SmmSecurePolicy.h>

//
// MMI Entry Base and Length in FV
//
EFI_PHYSICAL_ADDRESS  mMmiEntryBaseAddress  = 0;
UINTN                 mMmiEntrySize         = 0;

//
// Global variables and symbols pulled in from MmSupervisor
//
extern BOOLEAN mCetSupported;
extern BOOLEAN gPatchXdSupported;
extern BOOLEAN gPatchMsrIa32MiscEnableSupported;
extern BOOLEAN m5LevelPagingNeeded;

extern UINT32 mCetPl0Ssp;
extern UINT32 mCetInterruptSsp;
extern UINT32 mCetInterruptSspTable;

extern SMM_SUPV_SECURE_POLICY_DATA_V1_0   *FirmwarePolicy;

//
// Variables used by SMI Handler
//
IA32_DESCRIPTOR  gStmSmiHandlerIdtr;

VOID
EFIAPI
CpuSmmDebugEntry (
  IN UINTN  CpuIndex
  );

VOID
EFIAPI
CpuSmmDebugExit (
  IN UINTN  CpuIndex
  );

VOID
EFIAPI
SmiRendezvous (
  IN      UINTN  CpuIndex
  );

//
// EFER register LMA bit
//
#define LMA  BIT10

//
// Indicate SmBase for each Processors has been relocated or not. If TRUE,
// means no need to do the relocation in SmmCpuFeaturesInitializeProcessor().
//
BOOLEAN  mSmmCpuFeaturesSmmRelocated;

/**
  The common constructor function

  @retval EFI_SUCCESS      The constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
MmCpuFeaturesLibConstructorCommon (
  VOID
  )
{
  //
  // If gSmmBaseHobGuid found, means SmBase info has been relocated and recorded
  // in the SmBase array.
  //
  mSmmCpuFeaturesSmmRelocated = (BOOLEAN)(GetFirstGuidHob (&gSmmBaseHobGuid) != NULL);

  UINT16                          ExtHeaderOffset;
  EFI_FIRMWARE_VOLUME_HEADER      *FwVolHeader;
  EFI_FIRMWARE_VOLUME_EXT_HEADER  *ExtHeader;
  EFI_FFS_FILE_HEADER             *FileHeader;
  EFI_PEI_HOB_POINTERS            Hob;
  EFI_STATUS                      Status;
  BOOLEAN                         MmiEntryFound = FALSE;
  VOID                            *RawMmiEntryFileData;

  Hob.Raw = GetHobList ();
  if (Hob.Raw == NULL) {
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  do {
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, Hob.Raw);
    if (Hob.Raw != NULL) {
      FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)(Hob.FirmwareVolume->BaseAddress);

      DEBUG ((
        DEBUG_INFO,
        "[%a] Found FV HOB referencing FV at 0x%x. Size is 0x%x.\n",
        __FUNCTION__,
        (UINTN)FwVolHeader,
        FwVolHeader->FvLength
        ));

      ExtHeaderOffset = ReadUnaligned16 (&FwVolHeader->ExtHeaderOffset);
      if (ExtHeaderOffset != 0) {
        ExtHeader = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)((UINT8 *)FwVolHeader + ExtHeaderOffset);
        DEBUG ((DEBUG_INFO, "[%a]   FV GUID = {%g}.\n", __FUNCTION__, &ExtHeader->FvName));
      }

      //
      // If a MM_STANDALONE or MM_CORE_STANDALONE driver is in the FV. Add the drivers
      // to the dispatch list. Mark the FV with this driver as the Standalone BFV.
      //
      FileHeader = NULL;
      do {
        Status     =  FfsFindNextFile (
                        EFI_FV_FILETYPE_FREEFORM,
                        FwVolHeader,
                        &FileHeader
                        );
        if (!EFI_ERROR (Status)) {
          if (CompareGuid (&FileHeader->Name, &gMmiEntrySeaFileGuid)) {
            if (MmiEntryFound) {
              Status = EFI_ALREADY_STARTED;
              break;
            }
            Status = FfsFindSectionData (EFI_SECTION_RAW, FileHeader, &RawMmiEntryFileData, &mMmiEntrySize);
            if (!EFI_ERROR (Status)) {
              mMmiEntryBaseAddress  = (EFI_PHYSICAL_ADDRESS)(UINTN)RawMmiEntryFileData;
            } else {
              DEBUG ((DEBUG_ERROR, "[%a]   Failed to load MmiEntry [%g] in FV at 0x%p of %x bytes - %r.\n", __FUNCTION__, &gMmiEntrySeaFileGuid, FileHeader, FileHeader->Size, Status));
              break;
            }

            DEBUG ((
              DEBUG_INFO,
              "[%a]   Discovered MMI Entry for SPAM [%g] in FV at 0x%p of %x bytes.\n",
              __FUNCTION__,
              &gMmiEntrySeaFileGuid,
              mMmiEntryBaseAddress,
              mMmiEntrySize
              ));
            MmiEntryFound = TRUE;
          }

          if (MmiEntryFound) {
            // Job done, break out of the loop
            Status = EFI_SUCCESS;
            break;
          }
        }
      } while (!EFI_ERROR (Status));
      Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob));
    }
  } while (Hob.Raw != NULL);

  if (!MmiEntryFound) {
    DEBUG ((DEBUG_ERROR, "[%a]   Required entries for SPAM not found in any FV.\n", __FUNCTION__));
    Status = EFI_NOT_FOUND;
  } else {
    Status = EFI_SUCCESS;
  }

Done:
  return Status;
}

/**
  Called during the very first SMI into System Management Mode to initialize
  CPU features, including SMBASE, for the currently executing CPU.  Since this
  is the first SMI, the SMRAM Save State Map is at the default address of
  SMM_DEFAULT_SMBASE + SMRAM_SAVE_STATE_MAP_OFFSET.  The currently executing
  CPU is specified by CpuIndex and CpuIndex can be used to access information
  about the currently executing CPU in the ProcessorInfo array and the
  HotPlugCpuData data structure.

  @param[in] CpuIndex        The index of the CPU to initialize.  The value
                             must be between 0 and the NumberOfCpus field in
                             the System Management System Table (SMST).
  @param[in] IsMonarch       TRUE if the CpuIndex is the index of the CPU that
                             was elected as monarch during System Management
                             Mode initialization.
                             FALSE if the CpuIndex is not the index of the CPU
                             that was elected as monarch during System
                             Management Mode initialization.
  @param[in] ProcessorInfo   Pointer to an array of EFI_PROCESSOR_INFORMATION
                             structures.  ProcessorInfo[CpuIndex] contains the
                             information for the currently executing CPU.
  @param[in] CpuHotPlugData  Pointer to the CPU_HOT_PLUG_DATA structure that
                             contains the ApidId and SmBase arrays.
**/
VOID
EFIAPI
SmmCpuFeaturesInitializeProcessor (
  IN UINTN                      CpuIndex,
  IN BOOLEAN                    IsMonarch,
  IN EFI_PROCESSOR_INFORMATION  *ProcessorInfo,
  IN CPU_HOT_PLUG_DATA          *CpuHotPlugData
  )
{
  AMD_SMRAM_SAVE_STATE_MAP  *CpuState;

  //
  // No need to configure SMBASE if SmBase relocation has been done.
  //
  if (!mSmmCpuFeaturesSmmRelocated) {
    //
    // Configure SMBASE.
    //
    CpuState = (AMD_SMRAM_SAVE_STATE_MAP *)(UINTN)(
                                                   SMM_DEFAULT_SMBASE +
                                                   SMRAM_SAVE_STATE_MAP_OFFSET
                                                   );
    if ((CpuState->x86.SMMRevId & 0xFFFF) == 0) {
      CpuState->x86.SMBASE = (UINT32)CpuHotPlugData->SmBase[CpuIndex];
    } else {
      CpuState->x64.SMBASE = (UINT32)CpuHotPlugData->SmBase[CpuIndex];
    }
  }

  //
  // No need to program SMRRs on our virtual platform.
  //
}

/**
  This function updates the SMRAM save state on the currently executing CPU
  to resume execution at a specific address after an RSM instruction.  This
  function must evaluate the SMRAM save state to determine the execution mode
  the RSM instruction resumes and update the resume execution address with
  either NewInstructionPointer32 or NewInstructionPoint.  The auto HALT restart
  flag in the SMRAM save state must always be cleared.  This function returns
  the value of the instruction pointer from the SMRAM save state that was
  replaced.  If this function returns 0, then the SMRAM save state was not
  modified.

  This function is called during the very first SMI on each CPU after
  SmmCpuFeaturesInitializeProcessor() to set a flag in normal execution mode
  to signal that the SMBASE of each CPU has been updated before the default
  SMBASE address is used for the first SMI to the next CPU.

  @param[in] CpuIndex                 The index of the CPU to hook.  The value
                                      must be between 0 and the NumberOfCpus
                                      field in the System Management System
                                      Table (SMST).
  @param[in] CpuState                 Pointer to SMRAM Save State Map for the
                                      currently executing CPU.
  @param[in] NewInstructionPointer32  Instruction pointer to use if resuming to
                                      32-bit execution mode from 64-bit SMM.
  @param[in] NewInstructionPointer    Instruction pointer to use if resuming to
                                      same execution mode as SMM.

  @retval 0    This function did modify the SMRAM save state.
  @retval > 0  The original instruction pointer value from the SMRAM save state
               before it was replaced.
**/
UINT64
EFIAPI
SmmCpuFeaturesHookReturnFromSmm (
  IN UINTN                 CpuIndex,
  IN SMRAM_SAVE_STATE_MAP  *CpuState,
  IN UINT64                NewInstructionPointer32,
  IN UINT64                NewInstructionPointer
  )
{
  UINT64                    OriginalInstructionPointer;
  AMD_SMRAM_SAVE_STATE_MAP  *CpuSaveState;

  CpuSaveState = (AMD_SMRAM_SAVE_STATE_MAP *)CpuState;
  if ((CpuSaveState->x86.SMMRevId & 0xFFFF) == 0) {
    OriginalInstructionPointer = (UINT64)CpuSaveState->x86._EIP;
    CpuSaveState->x86._EIP     = (UINT32)NewInstructionPointer;
    //
    // Clear the auto HALT restart flag so the RSM instruction returns
    // program control to the instruction following the HLT instruction.
    //
    if ((CpuSaveState->x86.AutoHALTRestart & BIT0) != 0) {
      CpuSaveState->x86.AutoHALTRestart &= ~BIT0;
    }
  } else {
    OriginalInstructionPointer = CpuSaveState->x64._RIP;
    if ((CpuSaveState->x64.EFER & LMA) == 0) {
      CpuSaveState->x64._RIP = (UINT32)NewInstructionPointer32;
    } else {
      CpuSaveState->x64._RIP = (UINT32)NewInstructionPointer;
    }

    //
    // Clear the auto HALT restart flag so the RSM instruction returns
    // program control to the instruction following the HLT instruction.
    //
    if ((CpuSaveState->x64.AutoHALTRestart & BIT0) != 0) {
      CpuSaveState->x64.AutoHALTRestart &= ~BIT0;
    }
  }

  return OriginalInstructionPointer;
}

/**
  Return the size, in bytes, of a custom SMI Handler in bytes.  If 0 is
  returned, then a custom SMI handler is not provided by this library,
  and the default SMI handler must be used.

  @retval 0    Use the default SMI handler.
  @retval > 0  Use the SMI handler installed by
               SmmCpuFeaturesInstallSmiHandler(). The caller is required to
               allocate enough SMRAM for each CPU to support the size of the
               custom SMI handler.
**/
UINTN
EFIAPI
SmmCpuFeaturesGetSmiHandlerSize (
  VOID
  )
{
  return mMmiEntrySize;
}

/**
  Install a custom SMI handler for the CPU specified by CpuIndex.  This
  function is only called if SmmCpuFeaturesGetSmiHandlerSize() returns a size
  is greater than zero and is called by the CPU that was elected as monarch
  during System Management Mode initialization.

  @param[in] CpuIndex   The index of the CPU to install the custom SMI handler.
                        The value must be between 0 and the NumberOfCpus field
                        in the System Management System Table (SMST).
  @param[in] SmBase     The SMBASE address for the CPU specified by CpuIndex.
  @param[in] SmiStack   The stack to use when an SMI is processed by the
                        the CPU specified by CpuIndex.
  @param[in] StackSize  The size, in bytes, if the stack used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtBase    The base address of the GDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtSize    The size, in bytes, of the GDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtBase    The base address of the IDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtSize    The size, in bytes, of the IDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] Cr3        The base address of the page tables to use when an SMI
                        is processed by the CPU specified by CpuIndex.
**/
IA32_DESCRIPTOR                *mGdtrPtr;
extern UINTN  mMaxNumberOfCpus;
VOID
EFIAPI
SmmCpuFeaturesInstallSmiHandler (
  IN UINTN   CpuIndex,
  IN UINT32  SmBase,
  IN VOID    *SmiStack,
  IN UINTN   StackSize,
  IN UINTN   GdtBase,
  IN UINTN   GdtSize,
  IN UINTN   IdtBase,
  IN UINTN   IdtSize,
  IN UINT32  Cr3
  )
{
  PER_CORE_MMI_ENTRY_STRUCT_HDR *SmiEntryStructHdrPtr = NULL;
  UINT32                        SmiEntryStructHdrAddr;
  UINT32                        WholeStructSize;
  UINT16                        *FixStructPtr;
  UINT32                        *Fixup32Ptr;
  UINT64                        *Fixup64Ptr;
  UINT8                         *Fixup8Ptr;
  UINT32                        tSmiStack;

  if (mGdtrPtr == NULL) {
    mGdtrPtr = AllocateZeroPool (sizeof (IA32_DESCRIPTOR) * mMaxNumberOfCpus);
    if (mGdtrPtr == NULL) {
      DEBUG ((DEBUG_ERROR, "mGdtrPtr == NULL\n"));
      return;
    }
  }

  //
  // Initialize values in template before copy
  //
  tSmiStack                = (UINT32)((UINTN)SmiStack + StackSize - sizeof (UINTN));
  if ((gStmSmiHandlerIdtr.Base == 0) && (gStmSmiHandlerIdtr.Limit == 0)) {
    gStmSmiHandlerIdtr.Base  = IdtBase;
    gStmSmiHandlerIdtr.Limit = (UINT16)(IdtSize - 1);
  } else {
    ASSERT (gStmSmiHandlerIdtr.Base == IdtBase);
    ASSERT (gStmSmiHandlerIdtr.Limit == (UINT16)(IdtSize - 1));
  }

  //
  // Set the value at the top of the CPU stack to the CPU Index
  //
  *(UINTN *)(UINTN)tSmiStack = CpuIndex;

  //
  // Copy template to CPU specific SMI handler location from what is located from the FV
  //
  CopyMem (
    (VOID *)((UINTN)SmBase + SMM_HANDLER_OFFSET),
    (VOID *)mMmiEntryBaseAddress,
    mMmiEntrySize
    );

  mGdtrPtr[CpuIndex].Limit = (UINT16) GdtSize - 1;
  mGdtrPtr[CpuIndex].Base = (UINTN) GdtBase;

  // Populate the fix up addresses
  // Get Whole structure size
  WholeStructSize = (UINT32)*(EFI_PHYSICAL_ADDRESS *)(UINTN)(SmBase + SMM_HANDLER_OFFSET + mMmiEntrySize - sizeof(UINT32));

  // Get header address
  SmiEntryStructHdrAddr = (UINT32)(SmBase + SMM_HANDLER_OFFSET + mMmiEntrySize - sizeof(UINT32) - WholeStructSize);
  SmiEntryStructHdrPtr = (PER_CORE_MMI_ENTRY_STRUCT_HDR *)(UINTN)(SmiEntryStructHdrAddr);

  // Navegiate to the fixup arrays
  FixStructPtr = (UINT16 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUpStructOffset);
  Fixup32Ptr = (UINT32 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp32Offset);
  Fixup64Ptr = (UINT64 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp64Offset);
  Fixup8Ptr = (UINT8 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp8Offset);

  //Do the fixup
  Fixup32Ptr[FIXUP32_mPatchCetPl0Ssp] = mCetPl0Ssp;
  Fixup32Ptr[FIXUP32_GDTR] = (UINT32)(UINTN) &mGdtrPtr[CpuIndex];
  Fixup32Ptr[FIXUP32_CR3_OFFSET] = Cr3;
  Fixup32Ptr[FIXUP32_mPatchCetInterruptSsp] = mCetInterruptSsp;
  Fixup32Ptr[FIXUP32_mPatchCetInterruptSspTable] = mCetInterruptSspTable;
  Fixup32Ptr[FIXUP32_STACK_OFFSET_CPL0] = (UINT32)(UINTN)tSmiStack;
  Fixup32Ptr[FIXUP32_MSR_SMM_BASE] = SmBase;

  Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY] = (UINT64)CpuSmmDebugEntry;
  Fixup64Ptr[FIXUP64_SMM_DBG_EXIT] = (UINT64)CpuSmmDebugExit;
  Fixup64Ptr[FIXUP64_SMI_RDZ_ENTRY] = (UINT64)SmiRendezvous;
  Fixup64Ptr[FIXUP64_XD_SUPPORTED] = (UINT64)&gPatchXdSupported;
  Fixup64Ptr[FIXUP64_CET_SUPPORTED] = (UINT64)&mCetSupported;
  Fixup64Ptr[FIXUP64_SMI_HANDLER_IDTR] = (UINT64)&gStmSmiHandlerIdtr;

  Fixup8Ptr[FIXUP8_gPatchXdSupported] = gPatchXdSupported;
  Fixup8Ptr[FIXUP8_gPatchMsrIa32MiscEnableSupported] = gPatchMsrIa32MiscEnableSupported;
  Fixup8Ptr[FIXUP8_m5LevelPagingNeeded] = m5LevelPagingNeeded;
  Fixup8Ptr[FIXUP8_mPatchCetSupported] = mCetSupported;
}

/**
  Determines if MTRR registers must be configured to set SMRAM cache-ability
  when executing in System Management Mode.

  @retval TRUE   MTRR registers must be configured to set SMRAM cache-ability.
  @retval FALSE  MTRR registers do not need to be configured to set SMRAM
                 cache-ability.
**/
BOOLEAN
EFIAPI
SmmCpuFeaturesNeedConfigureMtrrs (
  VOID
  )
{
  return FALSE;
}

/**
  Disable SMRR register if SMRR is supported and
  SmmCpuFeaturesNeedConfigureMtrrs() returns TRUE.
**/
VOID
EFIAPI
SmmCpuFeaturesDisableSmrr (
  VOID
  )
{
  //
  // No SMRR support, nothing to do
  //
}

/**
  Enable SMRR register if SMRR is supported and
  SmmCpuFeaturesNeedConfigureMtrrs() returns TRUE.
**/
VOID
EFIAPI
SmmCpuFeaturesReenableSmrr (
  VOID
  )
{
  //
  // No SMRR support, nothing to do
  //
}

/**
  Processor specific hook point each time a CPU enters System Management Mode.

  @param[in] CpuIndex  The index of the CPU that has entered SMM.  The value
                       must be between 0 and the NumberOfCpus field in the
                       System Management System Table (SMST).
**/
VOID
EFIAPI
SmmCpuFeaturesRendezvousEntry (
  IN UINTN  CpuIndex
  )
{
  //
  // No SMRR support, nothing to do
  //
}

/**
  Check to see if an SMM register is supported by a specified CPU.

  @param[in] CpuIndex  The index of the CPU to check for SMM register support.
                       The value must be between 0 and the NumberOfCpus field
                       in the System Management System Table (SMST).
  @param[in] RegName   Identifies the SMM register to check for support.

  @retval TRUE   The SMM register specified by RegName is supported by the CPU
                 specified by CpuIndex.
  @retval FALSE  The SMM register specified by RegName is not supported by the
                 CPU specified by CpuIndex.
**/
BOOLEAN
EFIAPI
SmmCpuFeaturesIsSmmRegisterSupported (
  IN UINTN         CpuIndex,
  IN SMM_REG_NAME  RegName
  )
{
  ASSERT (RegName == SmmRegFeatureControl);
  return FALSE;
}

/**
  Returns the current value of the SMM register for the specified CPU.
  If the SMM register is not supported, then 0 is returned.

  @param[in] CpuIndex  The index of the CPU to read the SMM register.  The
                       value must be between 0 and the NumberOfCpus field in
                       the System Management System Table (SMST).
  @param[in] RegName   Identifies the SMM register to read.

  @return  The value of the SMM register specified by RegName from the CPU
           specified by CpuIndex.
**/
UINT64
EFIAPI
SmmCpuFeaturesGetSmmRegister (
  IN UINTN         CpuIndex,
  IN SMM_REG_NAME  RegName
  )
{
  //
  // This is called for SmmRegSmmDelayed, SmmRegSmmBlocked, SmmRegSmmEnable.
  // The last of these should actually be SmmRegSmmDisable, so we can just
  // return FALSE.
  //
  return 0;
}

/**
  Sets the value of an SMM register on a specified CPU.
  If the SMM register is not supported, then no action is performed.

  @param[in] CpuIndex  The index of the CPU to write the SMM register.  The
                       value must be between 0 and the NumberOfCpus field in
                       the System Management System Table (SMST).
  @param[in] RegName   Identifies the SMM register to write.
                       registers are read-only.
  @param[in] Value     The value to write to the SMM register.
**/
VOID
EFIAPI
SmmCpuFeaturesSetSmmRegister (
  IN UINTN         CpuIndex,
  IN SMM_REG_NAME  RegName,
  IN UINT64        Value
  )
{
  ASSERT (FALSE);
}

/**
  This function is hook point called after the gEfiSmmReadyToLockProtocolGuid
  notification is completely processed.
**/
VOID
EFIAPI
SmmCpuFeaturesCompleteSmmReadyToLock (
  VOID
  )
{
}

/**
  This API provides a method for a CPU to allocate a specific region for
  storing page tables.

  This API can be called more once to allocate memory for page tables.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns
  a pointer to the allocated buffer.  The buffer returned is aligned on a 4KB
  boundary.  If Pages is 0, then NULL is returned.  If there is not enough
  memory remaining to satisfy the request, then NULL is returned.

  This function can also return NULL if there is no preference on where the
  page tables are allocated in SMRAM.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer for page tables.
  @retval NULL      Fail to allocate a specific region for storing page tables,
                    Or there is no preference on where the page tables are
                    allocated in SMRAM.

**/
VOID *
EFIAPI
SmmCpuFeaturesAllocatePageTableMemory (
  IN UINTN  Pages
  )
{
  return NULL;
}
