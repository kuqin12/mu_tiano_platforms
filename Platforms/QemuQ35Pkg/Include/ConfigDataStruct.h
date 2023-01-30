/** @file

  Platform Configuration C Struct Header File.

  Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

  This file is automatically generated. Please do NOT modify !!!

**/

#ifndef __CONFIG_DATA_STRUCT_H__
#define __CONFIG_DATA_STRUCT_H__

#pragma pack(1)



#define    CDATA_PLATFORM_TAG             0x280
#define    CDATA_GFX_TAG                  0x300



typedef struct {
  
  /* Platform Name */
  UINT64                      PlatformName;

} PLATFORM_CFG_DATA;


typedef struct {
  
  /* Power on GFX port 0 */
  UINT16                      PowerOnPort0;

} GFX_CFG_DATA;

#pragma pack()

#endif
