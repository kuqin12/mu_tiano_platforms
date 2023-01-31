# Overview

This feature branch is intended to enable PXE boot with lwIP backed multi-threaded support on QEMU Q35 platform.

The upstream prototype is inherited from [edk2-staging branch](https://github.com/tianocore/edk2-staging/tree/MpNetworkStack).
Modified modules from staging branch has been rebased to the top of Project Mu BASECORE [release/202208](https://github.com/microsoft/mu_basecore/tree/release/202208)
and pushed to this [feature branch](https://github.com/kuqin12/mu_basecore/tree/mp_network).

Platform level integration branch is checked into [mp_pxe_q35 branch](https://github.com/kuqin12/mu_tiano_platforms/tree/mp_pxe_q35).

## Developer environment

Fundamental build instruction of mu_tiano_platforms build can be found [here](building.md)

Note that due to the inclusion of lwIP stack introduced in the feature basecore branch is included in the format of nested
package, the latest edk2 pip modules will complain about this hierachy and break the build. To mitigate this error message,
please use the following command in the console session before building:

```bash
set PYTOOL_TEMPORARILY_IGNORE_NESTED_EDK_PACKAGES=TRUE
```

## Run This Branch To Perform PXE Boot

This branch has modified its registered boot options to have one and only PXE boot option, thus a normal launching command
as `PlatformBuild.py --flashrom` or `PlatformBuild.py --flashonly` should directly boot the system via PXE path to the locally
built UEFI shell app.

Since this exercising multi-processor execution, the default number of cores is set to 4 cores in `BLD_*_QEMU_CORE_NUM`.
One can override this value at command line during launch time to change this setting for more cores.

The `QemuRunner.py` script support GDB server enablement, and one can connect to the running QEMU with Windbg following instructions
[here](debugging.md)

## Setting Up Local PXE Folder

1. Kindly follow [this link](https://learn.microsoft.com/en-us/windows/deployment/configure-a-pxe-server-to-load-windows-pe#pxe-boot-process-summary)
to setup a local PXE folder of WinPE image.

1. Before launching the QEMU session, specify `PXE_FOLDER_PATH=<absolute/path/to/pxe/folder>` and `PXE_BOOT_FILE=<relative/path/to/bootfile>`

Note: Not setting these options will leaven them as default, which is set to PXE boot the locally built UEFI shell.

1. Once system boots to BDS phase, the PXE driver will reach to QEMU emulated TFTP server and proceed with PXE boot process.

## Known Issues

1. The memory protection feature from MU_BASECORE is [disabled](../../PlatformPei/Platform.c#L838) because:

    - QEMU provided undi driver for e1000 is not 4K aligned and thus will be blocked by memory protection policy.
    - A [staging branch change in DXE core](https://github.com/tianocore/edk2-staging/commit/a177b463201b1152f04557e71196c7fe13fdb2f4#diff-59ad9c9deae518651b9c763ad1ffdf86f552c79e884b65215a03861e352a2206)
    could cause self recursion on the protocol spin lock acquisition and block the system from booting.

1. The PXE boot may not always succeed. It is possible to run into page fault on secondary cores during data downloading
process. This issue is still under investigation could be caused by the QEMU undi driver not thread safe.
