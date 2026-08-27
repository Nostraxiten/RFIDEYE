"""Canned client output for ``rfideye --demo`` and the test-suite.

There is no device behind this: it exists so the interface can be explored,
screenshotted and regression-tested on a machine with no Proxmark3 attached.
The strings below are representative Iceman client output.
"""

from __future__ import annotations

from typing import Final

HW_VERSION: Final[str] = """\
[=] Client .......... Iceman/master/v4.18994 2024-05-01
[=] Bootrom ......... Iceman/master/v4.18994
[=] OS .............. Iceman/master/v4.18994
[=] Target .......... PM3 RDV4
[=] Hardware ........ device: PM3 RDV4, fpga: LF image 2s30vq100
"""

HW_STATUS: Final[str] = """\
[=] Memory
[=]   BigBuf_size................. 40559
[=] Current CPU speed ............ 24 MHz
"""

HF_SEARCH_MIFARE: Final[str] = """\
[|] Searching for ISO14443-A tag...
[+] UID: 04 3B 1A 2C 5E 60 80
[+] ATQA: 00 44
[+] SAK: 00 [2]
[+] Possible types:
[+]    MIFARE Ultralight EV1 48bytes
[+] Valid ISO 14443-A tag found
"""

HF_14A_INFO: Final[str] = """\
[+]  UID: 04 3B 1A 2C 5E 60 80
[+] ATQA: 00 44
[+]  SAK: 00 [2]
[=] MANUFACTURER : NXP Semiconductors Germany
[=] --- Tag Signature
[=]   IC signature public key name: NXP NTAG21x (2013)
"""

HF_MFU_INFO: Final[str] = """\
[=] --- Tag Information
[=]        TYPE: NTAG 215 504bytes (NT2H1511G0DU)
[=]         UID: 04 3B 1A 2C 5E 60 80
[=]     Version: 00 04 04 02 01 00 11 03
[=] --- Tag Signature
"""

HF_SEARCH_CALYPSO: Final[str] = """\
[|] Searching for ISO14443-B tag...
[+]  PUPI: 8A 24 55 01
[+] Application Data: 05 00 00 00
[+] Protocol Info : 33 81 71
[+] Answers to Calypso
[+] Valid ISO 14443-B tag found
"""

HF_14B_INFO: Final[str] = """\
[+]  PUPI: 8A 24 55 01
[+] Application Data: 05 00 00 00
[+] Protocol Info : 33 81 71
[=]  Calypso card detected (CD97 B)
"""

LF_SEARCH_EM410X: Final[str] = """\
[=] NOTE: some demods output possible binary
[+] EM 410x ID 1A2B3C4D5E
[+] EM410x ( RF/64 )
[=] Valid EM410x ID found!
"""

LF_SEARCH_EMPTY: Final[str] = """\
[-] No known 125/134 kHz tags found!
"""

HF_SEARCH_EMPTY: Final[str] = """\
[-] No known/supported 13.56 MHz tags found
"""

MFU_DUMP: Final[str] = """\
[=] ----+-------------+-------------------
[=]   0 | 04 3B 1A 2C | ....
[=]   1 | 5E 60 80 00 | ....
[=]   2 | 00 00 00 00 | ....
[=]   3 | E1 10 3E 00 | ..>.
"""

#: Command -> canned stdout.  Anything missing is reported as "no demo data".
DEMO_RESPONSES: Final[dict[str, str]] = {
    "hw version": HW_VERSION,
    "hw status": HW_STATUS,
    "hw tune": "[+] LF antenna: 32.14 V @ 125.00 kHz\n[+] HF antenna: 26.80 V @ 13.56 MHz\n",
    "hf search": HF_SEARCH_MIFARE,
    "hf 14a info": HF_14A_INFO,
    "hf mfu info": HF_MFU_INFO,
    "hf mfu dump --ns": MFU_DUMP,
    "hf 14b info": HF_14B_INFO,
    "lf search": LF_SEARCH_EM410X,
}
