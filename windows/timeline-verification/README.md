# Timeline Verification

Writing about history requires timeline information to get an accurate depiction of events. Let's collect some basic details on the files included throughout Windows versions to help establish timeline information on its development.

## Methods

### DLL Imports/Exports

Contained are the imports and/or exports of:

- Windows 3.1 (released 1992) `KRNL286.EXE`/`KRNL386.EXE` (16-bit and 32-bit base DLLs)
- Windows NT 3.1 (released 1993 as the first Windows NT version) `NTDLL.dll` and `KERNEL32.dll`

We get the files from the [v86 Windows 3.1 machine](https://copy.sh/v86/?profile=windows31) (click "Get hard disk image", not all machines have this button) and from this [Windows NT 3.1 VirtualBox image](https://archive.org/details/windows-nt-3.1_202208). For the latter, convert the VDI file to a hard disk image with `qemu-img` (`qemu-img convert -f vdi -O raw 'Windows NT 3.1.vdi' 'Windows NT 3.1.img'`) then mount the image to extract files. We use the `exehdr` tool to get MS-DOS EXE information (obtained by installing an [early version of the VC/VC++ development tools](https://winworldpc.com/product/visual-c/1x)) and the `dumpbin` tool to get DLL information (obtained by installing Visual Studio with the C++ development pack).

Note that MS-DOS EXE pseudo-DLLs did not support imports because Windows 3.1 did not have a dynamic linking mechanism. An EXE had to manually load another EXE, for instance by calling `LoadLibrary`, to use its functionality.
