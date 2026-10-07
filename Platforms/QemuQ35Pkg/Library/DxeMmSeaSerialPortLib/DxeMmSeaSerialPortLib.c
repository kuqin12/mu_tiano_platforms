/** @file
  SEA Serial Port Library.

  Copyright (c) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/PciSegmentLib.h>
#include <Library/PlatformHookLib.h>
#include <Library/SerialPortLib.h>
#include <Library/TimerLib.h>

#include <IndustryStandard/Pci.h>

//
// UART register offsets and bitfields
//
// TX Buffer
#define TXBUF_OFFSET  0x00
// Modem Control Register
#define MCR_OFFSET  0x10
// UART Status Register
#define USR_OFFSET  0x7C
// Component Type Register
#define CTR_OFFSET  0xFC

//
// Timing Related Constants
//
#define DELAY_INTERVAL  10         // Delay interval between writes
#define WRITE_TIMEOUT   1000000    // Timeout for writing to the serial port in microseconds

//
// LNL UART Device IDs
//
#define LNL_UART_COMPONENT_ID_CODE  0x44570110

// LNL Serial IO UART Device IDs
#define LNL_UART0_DEV_ID  0xA825
#define LNL_UART1_DEV_ID  0xA826
#define LNL_UART2_DEV_ID  0xA852

typedef struct {
  UINT32    Bar0;
  UINT32    Bar1;
} SERIAL_IO_CONTROLLER_DESCRIPTOR;

GLOBAL_REMOVE_IF_UNREFERENCED CONST SERIAL_IO_CONTROLLER_DESCRIPTOR  mLnlUartFixedAddress[] = {
  { 0xFE020000 + 0xC000,  0xFE020000 + 0xD000  },
  { 0xFE020000 + 0xE000,  0xFE020000 + 0xF000  },
  { 0xFE020000 + 0x10000, 0xFE020000 + 0x11000 }
};

UINT64   mSerialPortPciCfgBaseAddress = 0;
UINT64   mSerialPortBaseAddress       = 0xFE02F000;     // Default address for Serial IO UART (UART1)
BOOLEAN  mAccessMode32bit             = FALSE;
BOOLEAN  mUartInitialized             = FALSE;

// UART Status Register (USR)
typedef union {
  struct {
    UINT8    BUSY     : 1; // [RO][0] N/A
    UINT8    TFNF     : 1; // [RO][1] Transmit FIFO Not Full. This is used to indicate that the transmit FIFO in not full.
                           //      0 = Transmit FIFO is full
                           //      1 = Transmit FIFO is not full
    UINT8    TFE      : 1; // [RO][2] Transmit FIFO Empty. This is used to indicate that the transmit FIFO is completely empty.
                           //      0 = Transmit FIFO is not empty
                           //      1 = Transmit FIFO is empty
    UINT8    RFNE     : 1; // [RO][3] Receive FIFO Not Empty. This is used to indicate that the receive FIFO contains one or more entries.
                           //      0 = Receive FIFO is empty
                           //      1 = Receive FIFO is not empty
    UINT8    RFF      : 1; // [RO][4] Receive FIFO Full. This is used to indicate that the receive FIFO is completely full.
                           //      0 = Receive FIFO not full
                           //      1 = Receive FIFO Full
    UINT8    Reserved : 3; // [N/A][5:7]
  } Fields;
  UINT8    Data;
} SERIAL_IO_UART_USR;

// Modem Control Register (MCR)
typedef union {
  struct {
    UINT8    Reserved0 : 1;   // [N/A][0]
    UINT8    RTS       : 1;   // [RW][1] Request to Send.
    UINT8    Reserved1 : 2;   // [N/A][2:3]
    UINT8    LOOPBACK  : 1;   // [RW][4] LoopBack Bit. Puts UART is diagnostic mode.
    UINT8    AFCE      : 1;   // [RW][5] Auto Flow Control Enable.
                              // 0 = Auto Flow Control Mode disabled
                              // 1 = Auto Flow Control Mode enabled
    UINT8    Reserved2 : 2;   // [N/A][6:7]
  } Fields;
  UINT8    Data;
} SERIAL_IO_UART_MCR;

/**
  Gets the PCI configuration base address for the UART controller.

  @retval UART base address in PCI Segment Library representation
**/
UINT64
UartPciCfgBase (
  VOID
  )
{
  return PCI_SEGMENT_LIB_ADDRESS (
           0,
           0,
           30,  // Assume UART0 (FUNC 0) or UART1 (FUNC 1)
           1,   // Assume UART1 (FUNC 1)
           0
           );
}

/**
  Write a UART register.

  Register accesses are aligned to 1 or 4 bytes and have 8 or 32-bit size

  @param[in]  Offset         Register offset in 8 bit mode
  @param[in]  Data           Data to be written
**/
VOID
UartWriteRegister (
  IN UINTN  Offset,
  IN UINT8  Data
  )
{
  if (mAccessMode32bit) {
    MmioWrite32 ((UINTN)mSerialPortBaseAddress + Offset, Data);
  } else {
    MmioWrite8 ((UINTN)mSerialPortBaseAddress + Offset / 4, Data);
  }
}

/**
  Read a UART register.

  Register accesses are aligned to 1 or 4 bytes and have 8 or 32-bit size

  @param[in]  Offset         Register offset in 8bit mode

  @retval                    retrieved register value, always 8 bit regardless of access mode
**/
UINT8
UartReadRegister (
  IN UINTN  Offset
  )
{
  if (mAccessMode32bit) {
    return (UINT8)(0xFF & MmioRead32 ((UINTN)mSerialPortBaseAddress + Offset));
  }

  return MmioRead8 ((UINTN)mSerialPortBaseAddress + Offset / 4);
}

/**
  Serial port initialization.

  @retval RETURN_SUCCESS        The serial device was initialized.

**/
RETURN_STATUS
EFIAPI
UartInitialize (
  VOID
  )
{
  // Assume UART1 for now
  mSerialPortPciCfgBaseAddress = mLnlUartFixedAddress[1].Bar1;

  mSerialPortBaseAddress = (MmioRead32 (
                              (UINTN)mSerialPortPciCfgBaseAddress + PCI_BASE_ADDRESSREG_OFFSET
                              ) & 0xFFFFF000) +
                           LShiftU64 (MmioRead32 ((UINTN)mSerialPortPciCfgBaseAddress + PCI_BASE_ADDRESSREG_OFFSET + 4), 32);

  mAccessMode32bit = MmioRead32 ((UINTN)mSerialPortBaseAddress + CTR_OFFSET) == LNL_UART_COMPONENT_ID_CODE;

  mUartInitialized = TRUE;

  return RETURN_SUCCESS;
}

/**
  Initialization work needed for this SerialPortLib instance.

  @retval RETURN_SUCCESS        This library instance was initialized successfully.

**/
RETURN_STATUS
EFIAPI
SerialPortInitialize (
  VOID
  )
{
  PlatformHookSerialPortInitialize ();

  return UartInitialize ();
}

/**
  Checks if the Tx FIFO is not full

  @retval TRUE                 FIFO is not full
          FALSE                FIFO is full
**/
BOOLEAN
UartIsTxFifoNotFull (
  VOID
  )
{
  SERIAL_IO_UART_USR  Usr;

  Usr.Data = UartReadRegister (USR_OFFSET);
  return (BOOLEAN)Usr.Fields.TFNF;
}

/**
  Writes data to the serial device only if FIFO is ready for it

  @param[in]  Data             Data to transmit

  @retval TRUE             Data was sent out
          FALSE            No data transmitted
**/
BOOLEAN
UartTransmit (
  IN UINT8  Data
  )
{
  if (UartIsTxFifoNotFull ()) {
    UartWriteRegister (TXBUF_OFFSET, Data);
    return TRUE;
  }

  return FALSE;
}

/**
  Returns the UART Auto Flow Control status

  @retval     TRUE             AutoFlow Enabled
  @retval     FALSE            AutoFlow Disabled
**/
BOOLEAN
UartReadAutoFlow (
  VOID
  )
{
  SERIAL_IO_UART_MCR  Mcr;

  Mcr.Data = UartReadRegister (MCR_OFFSET);
  return (BOOLEAN)Mcr.Fields.AFCE;
}

/**
  Enables/Disables Auto Flow Control

  @param[in]  AutoFlow         TRUE - Enable, FALSE - Disable

**/
VOID
UartProgramAutoFlow (
  IN BOOLEAN  AutoFlow
  )
{
  SERIAL_IO_UART_MCR  Mcr;

  Mcr.Data        = UartReadRegister (MCR_OFFSET);
  Mcr.Fields.RTS  = 1;
  Mcr.Fields.AFCE = (AutoFlow ? 1 : 0);
  UartWriteRegister (MCR_OFFSET, Mcr.Data);
}

/**
  Write data from a given buffer to the serial device.

  Writes NumberOfBytes data bytes from Buffer to the serial device.

  The number of bytes actually written to the serial device is returned.

  - If the return value is less than NumberOfBytes, then the write operation failed.
  - If Buffer is NULL, then ASSERT().
  - If NumberOfBytes is zero, then return 0.

  @param[in]  Buffer           Pointer to the data buffer to be written.
  @param[in]  NumberOfBytes    Number of bytes to written to the serial device.

  @retval 0                NumberOfBytes is 0.
  @retval >0               The number of bytes written to the serial device.
                           If this value is less than NumberOfBytes, then the write operation failed.

**/
UINTN
EFIAPI
SerialPortWrite (
  IN UINT8  *Buffer,
  IN UINTN  NumberOfBytes
  )
{
  UINT32  Index;
  UINTN   Timeout;

  if ((Buffer == NULL) || (!mUartInitialized)) {
    return 0;
  }

  if (UartReadRegister (USR_OFFSET) == 0xFF) {
    return 0;
  }

  for (Index = 0, Timeout = WRITE_TIMEOUT; Index < NumberOfBytes; Index++) {
    while (!UartTransmit (Buffer[Index])) {
      //
      // Unsuccessful write so check if timeout has expired, if not,
      // stall for a bit, increment time elapsed, and try again
      //
      if (Timeout == 0) {
        // If Auto Flow is already disabled, and timeout was reached return
        if (UartReadAutoFlow () == FALSE) {
          return 0;
        }

        //
        // Disable AutoFlow Control if data did not come out of the FIFO in given time
        //
        UartProgramAutoFlow (FALSE);
        Timeout = WRITE_TIMEOUT;
      }

      MicroSecondDelay (DELAY_INTERVAL);
      if (Timeout > DELAY_INTERVAL) {
        Timeout -= DELAY_INTERVAL;
      } else {
        Timeout = 0;
      }
    }
  }

  return NumberOfBytes;
}

/**
  Read data from the serial device and save the data in a given buffer.

  Reads NumberOfBytes data bytes from a serial device into the buffer
  specified by Buffer. The number of bytes actually read is returned.

  - If the return value is less than NumberOfBytes, then the rest operation failed.
  - If Buffer is NULL, then ASSERT().
  - If NumberOfBytes is zero, then return 0.

  @param[out]  Buffer           Pointer to the data buffer to store the data read from the serial device.
  @param[in]   NumberOfBytes    Number of bytes which will be read.

  @retval 0                Read data failed, no data is to be read.
  @retval >0               Actual number of bytes read from serial device.

**/
UINTN
EFIAPI
SerialPortRead (
  OUT UINT8  *Buffer,
  IN  UINTN  NumberOfBytes
  )
{
  // Read is not supported with this instance.
  return 0;
}

/**
  Polls a serial device to see if there is any data waiting to be read.

  Polls a serial device to see if there is any data waiting to be read.
  If there is data waiting to be read from the serial device, then TRUE is returned.
  If there is no data waiting to be read from the serial device, then FALSE is returned.

  @retval TRUE             Data is waiting to be read from the serial device.
  @retval FALSE            There is no data waiting to be read from the serial device.

**/
BOOLEAN
EFIAPI
SerialPortPoll (
  VOID
  )
{
  // Polling is not supported with this instance.
  return FALSE;
}

/**
  Sets the control bits on a serial device.

  @param[in] Control                Sets the bits of Control that are settable.

  @retval RETURN_SUCCESS        The new control bits were set on the serial device.
  @retval RETURN_UNSUPPORTED    The serial device does not support this operation.
  @retval RETURN_DEVICE_ERROR   The serial device is not functioning correctly.

**/
RETURN_STATUS
EFIAPI
SerialPortSetControl (
  IN UINT32  Control
  )
{
  // Not supported with this instance.
  return RETURN_UNSUPPORTED;
}

/**
  Retrieve the status of the control bits on a serial device.

  @param[out] Control                A pointer to return the current control signals from the serial device.

  @retval RETURN_SUCCESS        The control bits were read from the serial device.
  @retval RETURN_UNSUPPORTED    The serial device does not support this operation.
  @retval RETURN_DEVICE_ERROR   The serial device is not functioning correctly.

**/
RETURN_STATUS
EFIAPI
SerialPortGetControl (
  OUT UINT32  *Control
  )
{
  // Not supported with this instance.
  return RETURN_UNSUPPORTED;
}

/**
  Sets the baud rate, receive FIFO depth, transmit/receice time out, parity,
  data bits, and stop bits on a serial device.

  @param[in,out] BaudRate           The requested baud rate. A BaudRate value of 0 will use the
                                    device's default interface speed.
                                    On output, the value actually set.
  @param[in,out]  ReveiveFifoDepth  The requested depth of the FIFO on the receive side of the
                                    serial interface. A ReceiveFifoDepth value of 0 will use
                                    the device's default FIFO depth.
                                    On output, the value actually set.
  @param[in,out]  Timeout           The requested time out for a single character in microseconds.
                                    This timeout applies to both the transmit and receive side of the
                                    interface. A Timeout value of 0 will use the device's default time
                                    out value.
                                    On output, the value actually set.
  @param[in,out]  Parity            The type of parity to use on this serial device. A Parity value of
                                    DefaultParity will use the device's default parity value.
                                    On output, the value actually set.
  @param[in,out]  DataBits          The number of data bits to use on the serial device. A DataBits
                                    value of 0 will use the device's default data bit setting.
                                    On output, the value actually set.
  @param[in,out]  StopBits          The number of stop bits to use on this serial device. A StopBits
                                    value of DefaultStopBits will use the device's default number of
                                    stop bits.
                                    On output, the value actually set.

  @retval RETURN_SUCCESS            The new attributes were set on the serial device.
  @retval RETURN_UNSUPPORTED        The serial device does not support this operation.
  @retval RETURN_INVALID_PARAMETER  One or more of the attributes has an unsupported value.
  @retval RETURN_DEVICE_ERROR       The serial device is not functioning correctly.

**/
RETURN_STATUS
EFIAPI
SerialPortSetAttributes (
  IN OUT UINT64              *BaudRate,
  IN OUT UINT32              *ReceiveFifoDepth,
  IN OUT UINT32              *Timeout,
  IN OUT EFI_PARITY_TYPE     *Parity,
  IN OUT UINT8               *DataBits,
  IN OUT EFI_STOP_BITS_TYPE  *StopBits
  )
{
  // Not supported with this instance.
  return RETURN_UNSUPPORTED;
}
