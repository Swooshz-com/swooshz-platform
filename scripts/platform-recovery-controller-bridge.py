#!/usr/bin/env python3
"""Repository-only recovery controller bridge with a fixed canonical locator package.

The operational surface is deliberately data-only at its boundary. The complete
canonical locator source is embedded below as a pinned raw-DEFLATE package. The
bridge never accepts caller executable source, never shells out to a provider,
and never selects a live Docker/SSH/backup/restore path. Tests use the explicit
synthetic fixtures in this module.

The state machine keeps the local controller/store ownership split explicit:
BOOT/READY/DISCOVERY are private authenticated protocol facts, EPOCH_READY and
RUNNER_STARTED are local spool frames, CAS is one-shot, RESTORE_BEGIN is local
durability evidence, and COMMIT is unreachable until remote/process/read finality.
"""

from __future__ import annotations

import base64
import builtins
import dataclasses
import hashlib
import hmac
import io
import json
import os
import queue
import re
import struct
import sys
import threading
import time
import types
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, BinaryIO, Callable, Mapping


# ---------------------------------------------------------------------------
# Fixed contract pins from the Run-342 G2 / Run-343 G3 FINAL CLEAR.

CANONICAL_REVISION = "c59446ecc57b8100efd84fbd8405317f4fe7978f"
CANONICAL_LOCATOR_PATH = "scripts/platform-persisted-locator-adapter.py"
CANONICAL_LOCATOR_BLOB = "c0b46e18bf75fcc31c4154e9dc53adac45b7fd91"
CANONICAL_LOCATOR_SOURCE_BYTES = 35994
CANONICAL_LOCATOR_SOURCE_LINES = 1019
CANONICAL_LOCATOR_SOURCE_SHA256 = "17925f1364565edbb39fa0f776e25d6f0410d8408d9bdce214143edf1d6f34d5"
CANONICAL_LOCATOR_COMPRESSED_BYTES = 8398
CANONICAL_LOCATOR_COMPRESSED_SHA256 = "5913fd800e89eff823cef6c08753154e5447eb0ff04eca68dac1668999d002ee"
CANONICAL_LOCATOR_ENCODED_BYTES = 11198
CANONICAL_LOCATOR_ENCODED_SHA256 = "44fba3ed738e696e83e72d0a406cb1d8652c21aaa49f583debb4d907fae05321"
CANONICAL_LOCATOR_WRAPPED_LITERAL_BYTES = 12260
CANONICAL_LOCATOR_PACKAGE_COMMITMENT = "49ff535562d62c7b06b02638685c8962e24714d873b8c75a2602a05d84ded386"

MAX_LOADER_SOURCE_BYTES = 28644
MAX_AUTH_FRAME_BYTES = 65536
AUTH_FRAME_HEADER_BYTES = 72
AUTH_FRAME_TAG_BYTES = 32
AUTH_FRAME_OVERHEAD = AUTH_FRAME_HEADER_BYTES + AUTH_FRAME_TAG_BYTES
MAX_AUTH_PAYLOAD_BYTES = MAX_AUTH_FRAME_BYTES - AUTH_FRAME_OVERHEAD
MAX_CONTROL_PAYLOAD_BYTES = 4096
PUBLIC_FRAME_HEADER_BYTES = 12
MAX_PUBLIC_PAYLOAD_BYTES = 4096
MAX_PUBLIC_FRAME_BYTES = PUBLIC_FRAME_HEADER_BYTES + MAX_PUBLIC_PAYLOAD_BYTES
MAX_SESSION_FRAMES = 16
MAX_SESSION_BYTES = 1048576
MAX_STDOUT_CAPTURE_BYTES = 4096
MAX_STDERR_CAPTURE_BYTES = 4096
MAX_COMBINED_CAPTURE_BYTES = MAX_STDOUT_CAPTURE_BYTES + MAX_STDERR_CAPTURE_BYTES
MAX_FILENAME_BYTES = 2048
MAX_MEMORY_BYTES = 524288

# Stable aliases make the mechanical ceilings unambiguous to offline callers.
LOADER_SOURCE_MAX_BYTES = MAX_LOADER_SOURCE_BYTES
AUTHENTICATED_FRAME_HEADER_BYTES = AUTH_FRAME_HEADER_BYTES
AUTHENTICATED_FRAME_HMAC_BYTES = AUTH_FRAME_TAG_BYTES
CONTROL_MAX_BYTES = MAX_CONTROL_PAYLOAD_BYTES
PUBLIC_SPLQ_HEADER_BYTES = PUBLIC_FRAME_HEADER_BYTES
PUBLIC_SPLQ_PAYLOAD_MAX_BYTES = MAX_PUBLIC_PAYLOAD_BYTES
READER_CHUNK_BYTES = 4096
EVENT_QUEUE_MAX_ENTRIES = 16

PUBLIC_SPLQ_MAGIC = b"SPLQ"
PUBLIC_SPLQ_VERSION = 1
PUBLIC_SPLQ_FLAGS = 0
PUBLIC_SPLQ_HEADER_STRUCT = struct.Struct("!4sBBHI")
assert PUBLIC_SPLQ_HEADER_STRUCT.size == PUBLIC_FRAME_HEADER_BYTES

FIXED_LOCATOR_NAMESPACE = "__canonical_locator_payload__"
FIXED_LOCATOR_IMPORTS = frozenset(
    {
        "__future__",
        "dataclasses",
        "datetime",
        "json",
        "queue",
        "re",
        "selectors",
        "struct",
        "subprocess",
        "sys",
        "threading",
        "time",
        "typing",
    }
)
FIXED_LOCATOR_TRANSITIVE_IMPORTS = frozenset({"_strptime"})

# This is the unpadded RFC-4648 representation of the deterministic raw
# DEFLATE package. It is split only for source readability; at runtime the
# value is exactly 11,198 ASCII bytes.
CANONICAL_LOCATOR_PACKAGE_B64 = (
    "7T1_d9tGjv_rU7C85llqaUVx0jbVrvJWkZXEW9tyJDlp6vj4aJGKuZEllaSSuFnfZz8A83s4lGQne7e3e-5rRHFmMBgMBoPBANB_fHN_lWf3L9L5_WT-wVte"
    "F5eL-cOa7_uD6XSWzpPdPJom3ujk8KX34YG3TLI8zYsk3p0tJlGxyLwojpZFkjVrtfFl4i1XF7N04i2zRbGYLGZemntxMksvkiwqktm1lyfLCB-9aba48gps"
    "kaUf8MXJIi_eZcno5aG3vIzypEnwFnNoFMVXaZ6ni7m3jIpLbwq96i2pOvbUFfVGBbxvAprLeiPwPl6mk8salEezfOEln5JskuZJ7MVplkwKgH9xTfAWbMDe"
    "ZDEvsmhSeNP0U7HKkryJ5KjVCOUwnK7wZRh66dVykRVeNJ8voD_oNq_V-Lu_5Yu5eP59lawS8SWTT3kyg94XWS5fFNlqUshvqwsg4iTJVfm1fCwusySK0_k7"
    "-SK9Shh-cVREk1mU50kuEJSvAhhRMotlxQSbabUSBaa4XgJ4UdadXwfe03QeZdcHg8DrRbNZdDFLarXaC8AjybwOx745oo-6_82j_OnTFwd-o3YUvQOG6HgX"
    "PvKQX3uFHART2fEe1Ib9l6f90Tgc9V70j7rhq_5wdDA4hqKHtVqvezw4Puh1D8PTcS98NhgedcdQ4t97s3vvavdePL73on3vqH1v1Lw3_c23qp90x-P-ECFl"
    "SXOyuFqms6Re8-Av889auz-ff350s8se9tTDWDy0Sw9vm-zpxxvoq1ETmNMoRuPucNzfh-c9eD86PRzTCJ51Dw7p7SOqftT9FWu39h7VTrpv2LdHrZ9_rL3U"
    "ngfac1977rHnxw9-3qsds-e91qPHtf6r_vE4BFRO-yHv4Mda7WTYDzmkHx_Rt778VhvC5w-1A8J2BP_-VDvqDp8fHNNQTp73BsfH_d44HB8c9QenY6o2Dl8M"
    "aKxD73tvz_vOO4DPEfzPWtaQ24BLRDUA9BMOubt_cNwfjcLe4Oioe7xPPPD2bTK5XJA4CU9Onx4e9EKs-CZ89eDt3K-xZwD7S38oecZVsfZ6eAAzHJ70j6GX"
    "58gYy2SOS8IXRYNf8O3ivXwxejEYEgvll8DU8nV_OBxgZ36SZYsMQHf3jw5GyIjh6-4BNcBPX3vf7fX6J1TCnvQynHYswU_9fe9wMCJ28NkTdPRbfzgIh4PX"
    "MOBx7wUWmW_82hEw08HJYd-sVX7rwywfvOqO--HhoNcdD4YhdcsIU1Hk1_q_dnvjwzfh4LiP9bSvgBww1fBNeDwYh_1f-71TxuB--a3Pa0p29_XvAOjk-eBk"
    "DBQYha-6h6fU0-4E5AXIm6tkXoQodBarovNTq9XyoCSNZ0kI4gulhCzc44Vj-P7bYp50YJUD7NroRf_wMHw97J6cEMdkOzs7eVJ4u8mqlk69M2_3D8__9vMJ"
    "MOZzWJvh6ag_bO_e-N75n1Dmz2E7SAtYF38C0cga6LX3n1LdbwDlyWIxS6fXdsMfqOGS7V15uIKF0PnW6K22miNCJ89pcbCP7v7-EB5PkB9Pnu93x92n3VEf"
    "HrEBFnRHo9eD4T5_fAaUlGCgxquDXl89YakniYzvR4dHg_0-ezruPx-MD7pYpkCMDnt96hqefum_YQ_DwWCsXveGh_Jh_0CNAgXfAYxthMXj3_AfEAL98ahP"
    "bA5yd4g49F50QY4cPj1gy_PkOUzQcfdIDQNA9497HM9fhk9Hw1dYTj10D49UT93T8QtPmxHPpG7yiXaoF4Ojfuf-HDjjE6on80IUKAp27sfJh_vz1Wymyixp"
    "19lTRZyenZ2vw6w7ADmZeKRsoeo0I5Vrmf8-897CxrT7K_v4yD7m7ON39tFlHwX7-OCBNCGhFY7Gg5POA_Z69xKYsHP_Q5Tdz1YAmbOkgL-Lw-r88OjhHv-O"
    "rDqPrpKO_63Bvj4vjy-olPO9AAKT11lG74DLQVtiL6febg1WHSxGUjJACyOFsI_StN7_NEmWqBs12rT9giL1FLU1VhU1OVQvAw9mblfoc1yj9KZROiP1i7Qv"
    "Dv2Ea5YMvN4X72EJtWTtl6sku-6BZkZqCaCxXbMR180Gq2K5Kja1iZOpF36IZimqUOEkgrGkMMHhqpgwnQPKVkmbtCj6ThtNCCoWvMR_z3TY56wOKFjJrI1q"
    "VVBreLtP8In1ClIKFE7Qd1MYVjSfJHWCH2CNhgcUdapCzSkw_lVUTC5Z9QYqzMfAnAwoqUYRqMUacvWp_5nQuMG62Kccm4fit0Eti-xagQDlHjXrjtQmQQnP"
    "lvggkHSpdQxQQqzivcJ6RAkvyhk2t0ExAo0P8MP-72O_foMdNagNwVGD6Hh1CRkAMeSb10mUtVuP4ptd8eYKDgSX7dae9iqOrumFrwEYi8LLxSqj0raEkM5X"
    "RWK-yxM4aMQlKE3VZpItRKUfY1Q8sUZDMIEaB-xPjMXuMpV0KMtSYF_olM9plsARZ67qcCaXPH4RZVmaZMThirlNNuUwqhYGZwdjOQeezyFz_rLXFgiqtEg_"
    "JGEaa_0GmxaUtpgIx3ReyKVE1FErglbWvMBlhI8t78-MtPD5897ew4c_7bUe_vj4h0c__fTD49bjbQmezmkIJnUJrk3ZfHKZxKuZNUIT6xJlS2Qp01XA9QgL"
    "m67iLGrTtYpu22DgkKEcYLn_KRzPcLepZKa1Ms-eBZf09sUQPdGXEhgAA88NDnEm6oZ5-kcC4gK-sY6byXyyiJO6vyqmu4_9hiHBToHLobBPVdZLstuhSvSC"
    "pfEMu7TFGpDIQrfjte7eX3K1LK79hhv0Ew8PoXcHvviARoA_kjUrQjEH6k0r3LvDCYh2MD2FUfGFUsfJm77siMwpwGdXS7VWsuRv0CScLIgBJQJiaaidlNHC"
    "VFN8VG-m6TwF7eavI7BwCDAl-PFqCfYzRPx9cp3Xl1Ga5W0PZHNxVkBRcoYKAQ77_Jz6jdNJod4JGuSrWdG2yoB9P99QOWpdAD3gki1Fsxp2I6cT5hvKsYCD"
    "kiWVA5R4s_FBcz61CqEzeIlYsFnWJosVc0LQ5hfikgRqoBkNaHA9W0RxG8x0RZLTqGE8VXKB1w54bZtHLbQJWd7Eu1rlhXeRsJYucVAknwoYAK_fjBNDBjhE"
    "wH6yWQSsw4iv--oVj6WEFZpE8RNUAfxEtSsF4-dtOgMrKlgdoWBFdhSYflgbfFhsqGjnwylpYjs2tkxpUIsL4mDipfBysXjfcTN1YGqLckl17DUWaPqOMQ98"
    "FYO9BzVNhkcziz6GfEaQAsZ01C2s-Yo3qNHYdob4Zu7pxHNODuL3Dds0CKPbTgYYodOZPRMOUcnImCVgaM6R_gTBtWxcwuJLVxDvdu0igj6QCLxKA7YPbg8F"
    "rrUKmGn0ln06dhQm2jrV4qSxXq9AUtFhCg68Qj2Eufzso3Lnw2bxgZmxfaWz4gbj32yJOlssXn4ZLZOyhgho1U1uP2Mdn5Mtihuf1akBV7_UY88kbue6SqtX"
    "tushVLctni3BLQfF4Ql0yuPSKMU2gorjxJlB03OD8_kUtBUZtNloVwzDmqW2jskNX0ZMeMh1NM1QIaV_b7-GqJlYQYLN6WUDThLs0qSJ_LolZakpoyfeZsyS"
    "IuEkvcLrlUCQPvBAccnBPkOHELjvmUXv4NqH83wIWLyDC7SOwGA1X0aT9wyxs7aG1rnkQ4KP_MHucZB5-CzDu1dqwvV-NXbCIkIC37VuNdpLdrXkWhzWeHR5"
    "Uiq6lURhPa-RK2AehHWblElJevH3Vve69OOzD2SwYNyOKPq-gGTHC0_3FuHeFthc6xx4rumggHm-ALYHBk-iq7Z258dxRUlC64BYW-ibUfwAKPEuATNpkfHG"
    "sOSoAJYnKsea2YJdHtapVBctQhuE13XWnTEeBraJ5bJYRzz5BHe2TGyW0GcmNTWEgGs1UYw3vm1g0UXEX16sptMkS_jGCWIiuvb-TkOAIeIHt8cZBEAFFu-r"
    "RIs6w5xfSWEJh4oUUM9MOBPsZJYnpfby8MR6LmtCcLUNZ3pkL4YDShebq8SaYbiY7wlg9B6HBiYqTlZvV4cYsC2atW40Ss1ZtSYoOFBF1DtrI9Tzcm1wBvDM"
    "OqUqeP0O5rLEHoAkRslwKf40csnb9eZ-Mo0AQXHkqzcqmwFrvcPLA8XBCgq7aMUbSLN9llxFcK6jORbsBPQj0yeYDWElw0nA6hPGopr92RCLW0kC5HbqIfYW"
    "ctFrwJGn5JjYQ1122PianU0uV_P3MPKS5Agsscjl8_feAye2BOeWiDF5CKwEmMGimV1buG3F1tRxw55SnaGphpOdORubFbFe-9w8fCiLduDBze-tDhvmaCeL"
    "1SwmioGGjTQvnzvAyoA2XeMwr68cIXBMakt2mczA5Fw35C4JOkE2y1yRXgFjpKjDiU0ppJ2otIFYRpJbrFRD3t11qVasipa1GtiIa1uw9wMDtoN_b7uX6xv4"
    "PwfjlHiCTT3RwlSSy9oCvwmlvRb9RipVZykzOyWZCdKCgzH2Zcc2eymckHRFwCGIAtldIMF9PS2aYfH_irNbcRZF7kkyO6-eJ017urvarC-1LQXZFoq1tCtw"
    "CYnGhpDJTm4rNvkfNqD0Ki2cGrUh89hVQyxsb_HqapnXpQksR1_EKJ-kaecZ-DfilQhzsQRR2Kn7AZ6O2z5sd7C4Fx_DeTRn9Rr2FYYhecbAjFzw6EKofLOx"
    "tTzijqG2eVNyqMN-hhs0Hzyahhi57tRLxX0DB85n7GKVzmIu0fRFyQ4M3sZJhAliS8aeTY31babg7Q2suFQhmXLE5NIrt1xqBYb5rKHOn3xIYI3I8KDJBlU-"
    "trD9XRs3d2UMNCsLf2VaWThCN2pTQO2AA2G37OhIkU7R7AsVuSODfqdGr-yTFe076gqU0dVRR90JbVVJXRw5e7UJgzu6gT63oXmfTf-8wCt74oFV2e1uF3ia"
    "f93NljZmfrI0sdFNnK5bHs1Ahs6ozpmDdxbQttULuyviPjkhXT6hw4Q2O4ExDYGT3oGc70YFaWF70whj6K3R_LoOV2ZXxkEZb6_Yy7mJXWMLBQzv4dBeMksk"
    "acl9G-1qs1WsfMrTGLy90sK8xSotF0ZgLhvkAHW0t0bZiS5tkgLTeZLE4MPuCQOgxJVA-VX3JGe-NmU-Moj72t6YWPcFqelEYPWi88KabkyW2XQRu74jxWZW"
    "hw4fLLmbupjUqOHCyajgvChWVUoIixVgISmdHswVwrdgBxbbbrUG1xhMsnbH3czfTNajW57cUxxifntpWnYmDjzdeXhbKckdBd1i0jEsBl3f5Liz8h0lpaDM"
    "xyxFbicdpPJoVLpRUKdibA-2BBZNgbZOAsgtx4KWohK_WWSF26lFTBcmoN5HvO0lP_iGZjJtTmer_JLOen-RYSPSr1OPrpHunCMSp-hO6rGgFFBRtIidGboc"
    "eiv0CuRhNhDWEjNnTG-2WCyZdye7Xs-u8BAKxAGnU6ACKarGNiThhgTXqslPlKj3QOSPfpCdquU5Ac8wYBY4zxcxHVFpJlQ5kScL0eV3lWt6C_7NFx8NW7Gw"
    "ftOgQ6c5Gf--U4_QKay4kK0hE31VCdXVKWrr66vx-KANteA-H4VNZR3Tf0ZZjKZNOR8OG4lnBzbYphbtMsyiePliWUyS7BEwHGeWBbjUL65ZA2edtHiitchI"
    "h1yDZPjGIM9XxshgJSn1zMiVwJPhKvKRAlXkN3L1vvnH4qbh9T_RucUR6KqmR_6Y3V1F2XvAlO1qVm8QWjg1mjbpyJN_TItLm-8aa8EqWcPg5snXHjQID-9J"
    "xyUvvnpHhTk6YHNzuoHeJhduWOIY_1QSDxUyudzbNx3F4191rGvRsKCt7arUDQvr4tu6gqz2FYoIaVt7YlDbtMFUbS72xrJhU_nuu3erKItzJs_tAAF5XyqD"
    "YEsS2MADoy8-Bo4-A9mRUyF4ip5iSdxjwFnfyhzCNmNool-kdlgEaj1mpn6Qu6jjXndkDaaMCMldtb9HS7x8qdPGzo3vToWqYj_CBmt2IdF7NUPqwFEJo2Y4"
    "VjTBqHslMFpRiWW52rIjdbF4FX2qtwINFr_KUt02ysDxvXWJJWGeN9YNyt28oalX82gJumNBCNjqfunmSGHpYiLOPaOEE0gsGpO5KhlnFl1dxJFdvY7Rrw2h"
    "2KJa8KUA-wognL8hdAsXE3pPcMtfyyy6JQODDUIE-2zBzrw-SnGfkct3MBcrafKe-BQa-6YFB6hUAQdKKuHY-yQ7fyijMdiX5-9BvsyFXBTdagd76scgq_d9"
    "R19HgGzV-mWOE63S7mSCe-L1jLuMcq_2WtRPdAvstXySc3hYShkMh5oTALjIrjyyAEHw1S4Bu08nLA8cZdDDHmxFcC2XQN-4ZjLwuS6085Dh6eE-GxrejO4T"
    "oqji3ON1pU87pBhnQXeTwS-6uULG-bUrqpMiyakKYgXzK4TRFDch3HeuQ6aw1N2bp8OkwGKYjMq67qfrhNsFiKjDK0MFbSXcu8qOijJ6PUMam92dGzcKPFFG"
    "-DvGItY1x0NlLZFsY0z5Ft6S2rNhPTLO_5V2o4roSF-k9hDBWOusRjQqDLyeAt--PoBYXWlIBCtcTCiD7WBEDq2j_iFE23p5M43h27Ph4EjWjkPcGS4gNhQG"
    "OHm_WlKjHKq9ftEf9qkNLGO20DGbQA4XWOhHFnsHI288PO1rJRJUGkvZbJXQdWvH2-kul2-P4BZolr8FHW4eRzNYrycyeHZHazulK7_5BIe70_IePIZMCPCf"
    "XiWPwMqZP3ShlOaILXHDjA8Rqz3rHo76Nbif08iWxaikgvXZpBtB62GgOJAEY0hWEIfyHWoZD7wxvtnz-gBMFYBuT0SUkLEgqALTEWBQ3Ujhyo2AHZ8eHpYA"
    "ladPm2wcjGZlrWACxq04qfDaMAqzhbAIYZ_I6pC9Q5ppPUgAgoHa3m-YsGAHg6oDb-cN_O0eHe3u7_tj_8WLvUfto4P2aNQ8Hfm_-TsNE7xt802awvi6kR9V"
    "HBKNBBv8dQBpMyrYPSf4cA0JKnglSGJPvhoYmyeKQylYCjiNR2ArNkOlnh3jvJ18NUGDhl6oEewJ0Qtu8I5OIFR_57Pu9ayaIC9oewNxRcI8t_7L2_lPSnzy"
    "_bc7WpWxqtJuz1dXED-KIurxw1br8Z5WjzhoapysgZX0gTwMwS4Nu5NjGau5wSKwEhMvasVsKeUgqfBKFJYwXIrExprS2fArLyoN9ParSudzx_oqL4PtAapZ"
    "XwvYXgCbOpB3E2Wg9spxrXlIlcNlPrv5pg2RxT7gFOyYomkncMiqHU3q7AQ2s5pca7amkRCrmHOlRmgKtNKfHHK5EGhAyFmgdwIXY-zoE_u1x6DD_vJBSPZY"
    "g-bXwld1traXNQMojUTwZBX2d8JYY_TtMBMyDiNn2hj6VbP3SimMar3hYDRiO4lTWv0JjwOaG5DyPkO9k7QvdzAyBaAZTZ54Lx0OXZuUQKbgVTvRULmIRMNM"
    "bHvSJYqKnHeCLgenUKiSzkHdMcB669Gtj7PUXJEYmo1_EDVNWnyPGbPmb9_-TimvNOMJXPst_kjmHTyqNqykJfsQhpHOOKEd97OVXjjcegl3dareemecbXxx"
    "buOKgwmdIG5r_xQ8atDVBnNFGS98VS5cb4w64iXmtsIbZbTlCkDmG72GDqr81hcefTJLgrY8jXQJZFG6bZoJFqkoLofAzPcg8PZutjmyTlVw_WfqertcE5wl"
    "rtV4YsYxdlC9k6FuHTEpB-KbclfzmDA8VLTXlkR2F1U2Uc4hWrn0xWDvbm6Xw2BBb6uiNkv7yhqOObOpca7717BXDXvpbAPWptm54U-jA9aILqLyLV-h0vJW"
    "9Uxvn8o17mqge-0YskhVVh4z_ygnNHuuDB_rr-N65mQlzQHN5ir0Ud7sfmYtyrrtkUgejZ4hNNcMeu__5qBdbpfWwEUVpQzZ6-hfbMrN7W3dsP_lJr28Z9_F"
    "F9PTk9TgnYh2GyJa8QxG2PjMIIQpkkxPSdN70PKAtJwdK-vq0sydqUY1PS8Ff9oTXI61QyVXDO2zgb-N403beRBzZ5PSiFYOvCzfHpWBObP_IFTjykPOm9Cj"
    "GGP4NrIbvS_X8F-lXzfrq6LYtde6SbWGg1wbsRvIWuZat01voLjT0GTv3hupW0FZZRxUjuBBKQlXsL6aTr5a2dvX_dY2hzUqdWRutLJUZC0nkzrMyNA2Gh3Q"
    "ZYPGbdCGlzTNg1sg30tjhJEuSWJJArbOPvTLsy11edbQTlzB3uKRd8CDxbAZewvn9JhdueFR1W_cSaFGx1SKzLJV6rI7uzOnCwNz1t59cH6Ha7CtUKSQoi3c"
    "pzfOtXKixsgtc5qZxSTkYTvMecDp22OkXIZpNNqxK_Gyc7XL_WKwxMz80HUPtQPOF_FiwpzHkkluOjjkl8lsFn7M0Bsgs8owl61IhWsVzRbvyBuf0cRuh0aj"
    "ByHdZ7uK9pxFeF2e2i_hqmGGVyva63VjHrHLk7taShjFbBL-75hNqgf5jHFaW93Wmvy1dixU-BfwmoX3YKwU7isW10o3IMONmLNqBaeT94WBjlga0Nc85CzI"
    "_XVZ6Jr6SYTmCVY6Iyl1bjq9WXXU3nLmM5hCn8HP3RT_5RdskPEYv1Fe5vySirGSkWH83PDkTucdvb-Dk75RjKmg15WD7KguhzBXNA92WubGRN4SQJiPC-Yu"
    "YbgOlV1UwLOE5pV-g6L5Ev915xFUSqEjvwhaGdvOxA96Thb8oYLbZHdguDVxv8JsqXwoN-1kMRU5Y1zZRgxXNRsOB8I3MJHeoeH0VHHsB5Uo0S8D8DyzDTkX"
    "3IuSz8X7dB5XToTpK3SnidGRw76CsneS7KehkJzMkmgOd81iKfFPbrIkLlaIcrli9QxXED3MAeDRjStGFkGCYwBCv86C6fBxX8y5H5O4v94VzrZ45QqdLqbK"
    "s4lhi6rRGSEQyNxBHLtAerZxTqiogT5rvMY5TyyRoJsugW-jKfIMJOs5pZkouCsTJR2nGnhSEHXNSAJWyo-MePaLRSA4tdE7qa3NXaNXbUYxHIgkJMXcxpLT"
    "HLD0ZBzrfa1kNvISOAz65wJmuZjN6g13-hxRh09akVg5a0oo6o0-RmlRF8nvW829hhVxtw5rHc77FBG8ZTfV4PX07NxpKyR35pDvScLbDDhFuaEG5O9dmPoX"
    "W5rkbE0vVeI3WVl1u8DEGDwkrSPcxXLhkCkdDYGt9DJ0snSWlVwU7R2Wx_3r_XKzaaLhoXZCcqy0sGLOy5D0gf90jJ4t0K6PmOr1-1b9qhFX1dFH7qzjpoAZ"
    "3geT4kYy0Okg2AGXglMiarNN8lGbbGMJiFQQxtIKtCiSjX6RzGqg-ZqGyN8h_LTTYvXuUnMVQkdkiLME5aUtf3np7Ow8YAEB50EpjdldNhd03oPuPd49Beqp"
    "X-TaBXJC_C6E8CEyHh73MGwHpVSB57bJLIUe2U-ikG3PkPZMiaAR1DFBWTnupSRd-F4HMl8ueEzk1Gq2fgiYO3yzFegJtzj0RqMkLRkR-pjO2iEvhUMq6tmw"
    "lQr1t26nq9RiNXg0nwolI8dxa254LL5Dl-VBIpXzWcqEE6jdP6TBVHS5brbPnSkP7IMQVHIfG9jxABpb5wNXiqYv8FrVs_aX1ouNWZ2LPYYbR6RF1hZihYo4"
    "GiRvCzOS6ZNIS99x_nJrR3oN8-Cth5GZmaNtBucdozXD5CNr_2Oja-oncvqhLkcd82xeVcs4pZcq0YAVUk36XsokqApRCmhqklYC8lcvYYArM_cxQ4zxyzG-"
    "INEyXYKqGcEmtppHH2DykeP9bbWiLbnHOgIY-2XF8itn9XNU0o3uNdv2rS_ZOkg1OvBZP-nWcOQVkD__1xzTUx3YD0RlxzwcgiKTvcMcQFKTNidO7BOwbcVR"
    "AuKGeZMwL_r6l_TGtHKTGbbtTbCpbhQy2LQSHeM0JtFhgHx-0gm80s_SbULMDhxHbJS2qGGuYt47VlygVsmKw7TCMLXQbjRw6vHMdoQq1rADnMt1jGhnuzia"
    "4IpxFDD-COEg7ipCpPQiy1hAv6nBIZtLcU7RNbp4vn10LE9Gn3I6u0Iz7T9ZJ3AW29qqDG5ruOuboZPOKhhO6SxwhFg66xlT3ykxg7uRxQ0dB4e4G5ps0jG_"
    "lps0XHeHck7A5ccOo21X0GLrbb0yJhKVQMcWv4szsMX5lRZ-IO8VKpRO2Ssk3AL9s-E83VZqmesy2lKH1WF8Bnfy-DslzLWrIyOqzwBajumrAspk9magXJ6W"
    "gdqSTf3MRzV6GOGF5j5HKl9dBJWCY53CrVTLSY7q_pRcWweJXY9z1LlZUIKm7zftO-Dq5E-n7ab6Cn9LqmxrjlkDoyyRKvajDXYXfmA2Ge4W4n2NaL-NWN8g"
    "0vmOFdTuIs5vLcrvJMZvIcJLO6-i9zaiW1Ma3MtEgsOVYiZuCEpZYxxr5bYKu_Aa3xBs2dDMgiIdo8tdvWEC1o52xnC5mmpdbBqKqq7J7rk0WV4iJaZhzidl"
    "tRTdK2zqpeMs--3lKhuk2ZOej8NS3pSRptST61iFvupoeIRzp1ryLtualTnbwk7_iqdIBa-cN110a7irYRR1nVysVQXbz1prihl1HXnQLbRK7M1yDIltCfvU"
    "dg386sIAe8cyrXv0PGSB34Cd3mkZpQsQMe-_liJjWc_KvOQ0o_07KjlfoJr8Eykdm9nZZTBfZ8G_-53F7dH7d5MwlCaRSd8nnU3idx2gOxMO1U2tvvhRqa0H"
    "vD2K1FOV3KtSAIz9uHxAZMc0lgd-c4IJh1645j5WufK5_e1k3yWrpPGz0TKLv5lVWybbtjhm84WQQ4hLc9bXoanZjN8T1F3EsT0WnXXKvpxKU3K3cLp16hXc"
    "Lp7uGq6Ur2bi8ztO1x3o6_qhDmHyrjzmVXlzcPOmcPoAvxX8Xfold39k80X57EP3TyMxPq4o5Bde8nJMv3eCFnD1tMVF0jktS-uajd9DGdeQoyT7AL_rgonr"
    "4KepUfby7KUioz-K4gSTYPHM5N4S8tRQRZnejRKdViTSEWA6rl-y0GkEtuJNHgaOhK8GJQMzWW7ZJbNhr7XadmCtxO4NMYmw7ybs2pHfY_LhOX9Qz8yqxFuX"
    "J7Ox5hpLih-WWrbjSARvnG1ZH2tFhV7PLS70GpXiQa9ULSLctaoyQ28t3Z0_n9DYQDoHqzAHX86FRrDE-tZuOje2ZC4TtpApuMPVreVqy5n8ml8ZNtmvdACj"
    "Xsudlr1CcMB4IaU3CUNSksMQgYchV5FZT7X_Bg"
)

# ---------------------------------------------------------------------------
# Safe errors, commitments, and bounded canonical serialization.

class BridgeError(Exception):
    """A symbolic failure which is safe to expose in public evidence."""

    def __init__(self, code: str, *, safety_state: str | None = None):
        self.code = str(code)
        self.safety_state = safety_state
        super().__init__(self.code)


class ProtocolError(BridgeError):
    pass


class PackageIntegrityError(BridgeError):
    pass


class StoreTransitionError(BridgeError):
    pass


class ResultClassification(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class RunnerControlCode(str, Enum):
    PRESTATE_FAILED = "PRESTATE_FAILED"
    BACKUP_NOT_QUALIFYING = "BACKUP_NOT_QUALIFYING"
    LOCATOR_NOT_FOUND = "LOCATOR_NOT_FOUND"
    LOCATOR_AMBIGUOUS = "LOCATOR_AMBIGUOUS"
    RESOURCE_COLLISION = "RESOURCE_COLLISION"
    RESOURCE_CREATE_FAILED = "RESOURCE_CREATE_FAILED"
    ISOLATION_FAILED = "ISOLATION_FAILED"
    CLEANUP_UNPROVEN = "CLEANUP_UNPROVEN"
    RESTORE_PRECONDITION_FAILED = "RESTORE_PRECONDITION_FAILED"
    RUNNER_ABORTED = "RUNNER_ABORTED"
    PROCEED_INVALID = "PROCEED_INVALID"
    RESULT_BEFORE_PROCEED = "RESULT_BEFORE_PROCEED"
    RESULT_DUPLICATE = "RESULT_DUPLICATE"
    RUNNER_TOP_LEVEL_EXCEPTION = "RUNNER_TOP_LEVEL_EXCEPTION"
    RUNNER_NO_RESULT = "RUNNER_NO_RESULT"
    RUNNER_NON_NONE_RETURN = "RUNNER_NON_NONE_RETURN"
    LOCAL_ABORT = "LOCAL_ABORT"


PUBLIC_ERROR_CODES = frozenset(
    {
        "BARRIER_INVALID",
        "PACKAGE_INVALID",
        "PACKAGE_DRIFT",
        "PACKAGE_COMMITMENT_MISMATCH",
        "FRAME_INVALID",
        "CONTROL_INVALID",
        "SESSION_LIMIT_EXCEEDED",
        "MEMORY_LIMIT_EXCEEDED",
        "BOOT_INVALID",
        "DISCOVERY_INVALID",
        "IMAGE_PROFILE_INVALID",
        "IMAGE_INSPECTION_FAILED",
        "IMAGE_ID_INVALID",
        "RESOURCE_COLLISION",
        "RESOURCE_CREATE_FAILED",
        "ISOLATION_FAILED",
        "CLEANUP_UNPROVEN",
        "LOCATOR_NOT_FOUND",
        "LOCATOR_AMBIGUOUS",
        "LOCATOR_FAILED",
        "ARTIFACT_INVALID",
        "ARTIFACT_REOPEN_FORBIDDEN",
        "STORE_STATE_INVALID",
        "STORE_TRANSITION_FAILED",
        "POST_CAS_UNCERTAIN",
        "PROCESS_CAPTURE_OVERFLOW",
        "PROCESS_TRAILING_OUTPUT",
        "PROCESS_STDERR_FORBIDDEN",
        "PROCESS_TERMINATION_UNCERTAIN",
        "PROCESS_EXIT_NONZERO",
        "PLATFORM_UNSUPPORTED",
        "LOCAL_ABORT",
        "PROTOCOL_FAILURE",
    }
    | {value.value for value in RunnerControlCode}
)


_COMMITMENT_RE = re.compile(r"sha256:v1:[0-9a-f]{64}\Z", re.ASCII)
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_BARRIER_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z",
    re.ASCII,
)


def _lp(*parts: str | bytes) -> bytes:
    result = bytearray()
    for part in parts:
        if isinstance(part, str):
            value = part.encode("utf-8", "strict")
        elif isinstance(part, bytes):
            value = part
        else:
            raise TypeError("commitment part must be text or bytes")
        result.extend(struct.pack("!I", len(value)))
        result.extend(value)
    return bytes(result)


def _commitment(domain: str, *parts: str | bytes) -> str:
    return "sha256:v1:" + hashlib.sha256(
        _lp("recovery-bridge.v1", domain, *parts)
    ).hexdigest()


def _bytes_commitment(domain: str, payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise TypeError("commitment payload must be bytes")
    return _commitment(domain, payload)


def _store_bytes_commitment(domain: str, payload: bytes) -> str:
    """Match ControllerStore.bytes_commitment for the one shared CAS datum."""

    if not isinstance(payload, bytes):
        raise TypeError("commitment payload must be bytes")
    return "sha256:v1:" + hashlib.sha256(
        _lp("recovery-commitment.v1", domain)
        + struct.pack("!I", len(payload))
        + payload
    ).hexdigest()


def _is_commitment(value: Any) -> bool:
    return isinstance(value, str) and _COMMITMENT_RE.fullmatch(value) is not None


def _canonical_json(value: Any, *, limit: int) -> bytes:
    def check(child: Any) -> None:
        if isinstance(child, float):
            raise ProtocolError("CONTROL_INVALID")
        if isinstance(child, dict):
            for key, item in child.items():
                if not isinstance(key, str):
                    raise ProtocolError("CONTROL_INVALID")
                check(item)
        elif isinstance(child, list):
            for item in child:
                check(item)
        elif isinstance(child, str):
            child.encode("utf-8", "strict")
        elif child is not None and type(child) not in (int, bool):
            raise ProtocolError("CONTROL_INVALID")

    check(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ProtocolError("CONTROL_INVALID") from error
    if len(encoded) > limit:
        raise ProtocolError("CONTROL_INVALID")
    return encoded


def _parse_canonical_json(payload: bytes, *, limit: int) -> Any:
    if not isinstance(payload, bytes) or not payload or len(payload) > limit:
        raise ProtocolError("CONTROL_INVALID")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ProtocolError("CONTROL_INVALID") from error
    if text[:1] in " \t\r\n" or text[-1:] in " \t\r\n":
        raise ProtocolError("CONTROL_INVALID")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ProtocolError("CONTROL_INVALID")
            result[key] = item
        return result

    def reject_constant(_value: str) -> None:
        raise ProtocolError("CONTROL_INVALID")

    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, RecursionError, ProtocolError, UnicodeError) as error:
        raise ProtocolError("CONTROL_INVALID") from error
    if end != len(text) or _canonical_json(value, limit=limit) != payload:
        raise ProtocolError("CONTROL_INVALID")
    return value


def validate_control_payload(payload: bytes) -> Any:
    """Validate one canonical private control payload at the exact ceiling."""

    return _parse_canonical_json(payload, limit=MAX_CONTROL_PAYLOAD_BYTES)


def encode_public_splq_frame(message_type: int, payload: bytes) -> bytes:
    if type(message_type) is not int or not 0 < message_type < 256:
        raise ProtocolError("PUBLIC_FRAME_INVALID")
    if not isinstance(payload, bytes) or len(payload) > MAX_PUBLIC_PAYLOAD_BYTES:
        raise ProtocolError("PUBLIC_FRAME_INVALID")
    return PUBLIC_SPLQ_HEADER_STRUCT.pack(
        PUBLIC_SPLQ_MAGIC,
        PUBLIC_SPLQ_VERSION,
        message_type,
        PUBLIC_SPLQ_FLAGS,
        len(payload),
    ) + payload


def decode_public_splq_frame(frame: bytes) -> tuple[int, bytes]:
    if not isinstance(frame, bytes) or len(frame) < PUBLIC_FRAME_HEADER_BYTES:
        raise ProtocolError("PUBLIC_FRAME_INVALID")
    try:
        magic, version, message_type, flags, payload_length = PUBLIC_SPLQ_HEADER_STRUCT.unpack(
            frame[:PUBLIC_FRAME_HEADER_BYTES]
        )
    except struct.error as error:
        raise ProtocolError("PUBLIC_FRAME_INVALID") from error
    if (
        magic != PUBLIC_SPLQ_MAGIC
        or version != PUBLIC_SPLQ_VERSION
        or flags != PUBLIC_SPLQ_FLAGS
        or payload_length > MAX_PUBLIC_PAYLOAD_BYTES
        or len(frame) != PUBLIC_FRAME_HEADER_BYTES + payload_length
    ):
        raise ProtocolError("PUBLIC_FRAME_INVALID")
    return message_type, frame[PUBLIC_FRAME_HEADER_BYTES:]


def validate_barrier_utc(value: Any) -> str:
    if not isinstance(value, str) or _BARRIER_RE.fullmatch(value) is None:
        raise ProtocolError("BARRIER_INVALID")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise ProtocolError("BARRIER_INVALID") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ProtocolError("BARRIER_INVALID")
    return value


def _validate_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise BridgeError("STORE_STATE_INVALID")
    return value


def _validate_private_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8", "strict")) > 4096:
        raise BridgeError("STORE_STATE_INVALID")
    return value


def _validate_image_id(value: Any) -> str:
    if not isinstance(value, str) or _IMAGE_ID_RE.fullmatch(value) is None:
        raise BridgeError("IMAGE_ID_INVALID")
    return value


def _git_blob_sha1(payload: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
    ).hexdigest()


def _read_field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value[name]
    return getattr(value, name)


# ---------------------------------------------------------------------------
# Complete canonical locator package verification and fixed compile boundary.

def _decode_locator_package(encoded: str) -> tuple[bytes, bytes]:
    if not isinstance(encoded, str) or len(encoded) != CANONICAL_LOCATOR_ENCODED_BYTES:
        raise PackageIntegrityError("PACKAGE_INVALID")
    if re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        raise PackageIntegrityError("PACKAGE_INVALID")
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        compressed = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=") != encoded:
            raise PackageIntegrityError("PACKAGE_INVALID")
        source = zlib.decompress(compressed, -15)
    except (ValueError, zlib.error, PackageIntegrityError) as error:
        if isinstance(error, PackageIntegrityError):
            raise
        raise PackageIntegrityError("PACKAGE_INVALID") from error
    return compressed, source


def verify_canonical_locator_package(encoded_package: str | None = None) -> bytes:
    """Verify the complete pinned package and return its exact source bytes.

    The optional argument exists only for offline drift fixtures. The actual
    bridge path never accepts caller package/source bytes and always invokes this
    verifier with the module-owned literal.
    """

    encoded = CANONICAL_LOCATOR_PACKAGE_B64 if encoded_package is None else encoded_package
    compressed, source = _decode_locator_package(encoded)
    if len(compressed) != CANONICAL_LOCATOR_COMPRESSED_BYTES:
        raise PackageIntegrityError("PACKAGE_DRIFT")
    if hashlib.sha256(compressed).hexdigest() != CANONICAL_LOCATOR_COMPRESSED_SHA256:
        raise PackageIntegrityError("PACKAGE_DRIFT")
    if hashlib.sha256(encoded.encode("ascii")).hexdigest() != CANONICAL_LOCATOR_ENCODED_SHA256:
        raise PackageIntegrityError("PACKAGE_DRIFT")
    if len(source) != CANONICAL_LOCATOR_SOURCE_BYTES:
        raise PackageIntegrityError("PACKAGE_DRIFT")
    if len(source.splitlines()) != CANONICAL_LOCATOR_SOURCE_LINES:
        raise PackageIntegrityError("PACKAGE_DRIFT")
    if hashlib.sha256(source).hexdigest() != CANONICAL_LOCATOR_SOURCE_SHA256:
        raise PackageIntegrityError("PACKAGE_DRIFT")
    if _git_blob_sha1(source) != CANONICAL_LOCATOR_BLOB:
        raise PackageIntegrityError("PACKAGE_DRIFT")
    if CANONICAL_LOCATOR_PACKAGE_COMMITMENT != (
        "49ff535562d62c7b06b02638685c8962e24714d873b8c75a2602a05d84ded386"
    ):
        raise PackageIntegrityError("PACKAGE_COMMITMENT_MISMATCH")
    return source


CANONICAL_LOCATOR_PACKAGE, CANONICAL_LOCATOR_SOURCE = _decode_locator_package(
    CANONICAL_LOCATOR_PACKAGE_B64
)
if verify_canonical_locator_package() != CANONICAL_LOCATOR_SOURCE:
    raise PackageIntegrityError("PACKAGE_DRIFT")
CANONICAL_LOCATOR_SOURCE_COMMITMENT = "sha256:v1:" + CANONICAL_LOCATOR_SOURCE_SHA256
# The FINAL CLEAR records this package attestation without the transport
# prefix; the bridge carries it as the store-compatible opaque commitment.
CANONICAL_LOCATOR_PACKAGE_BINDING = "sha256:v1:" + CANONICAL_LOCATOR_PACKAGE_COMMITMENT


def _fixed_import(
    name: str,
    globals_value: Mapping[str, Any] | None = None,
    locals_value: Mapping[str, Any] | None = None,
    fromlist: tuple[str, ...] = (),
    level: int = 0,
) -> Any:
    root = name.split(".", 1)[0]
    caller = globals_value.get("__name__") if isinstance(globals_value, Mapping) else None
    if level != 0 or (
        caller == FIXED_LOCATOR_NAMESPACE
        and root not in FIXED_LOCATOR_IMPORTS
        and root not in FIXED_LOCATOR_TRANSITIVE_IMPORTS
    ):
        raise ImportError("fixed locator import denied")
    return builtins.__import__(name, globals_value, locals_value, fromlist, level)


_FIXED_BUILTINS = dict(vars(builtins))
_FIXED_BUILTINS["__import__"] = _fixed_import


def compile_canonical_locator_namespace() -> dict[str, Any]:
    source = verify_canonical_locator_package()
    namespace: dict[str, Any] = {
        "__name__": FIXED_LOCATOR_NAMESPACE,
        "__file__": CANONICAL_LOCATOR_PATH,
        "__package__": None,
        "__builtins__": dict(_FIXED_BUILTINS),
    }
    module = types.ModuleType(FIXED_LOCATOR_NAMESPACE)
    module.__dict__.update(namespace)
    sys.modules[FIXED_LOCATOR_NAMESPACE] = module
    try:
        code = compile(
            source,
            CANONICAL_LOCATOR_PATH,
            "exec",
            dont_inherit=True,
        )
        exec(code, module.__dict__, module.__dict__)
    except (SyntaxError, TypeError, ValueError, ImportError, MemoryError) as error:
        raise PackageIntegrityError("PACKAGE_INVALID") from error
    namespace = module.__dict__
    if namespace.get("__name__") == "__main__":
        raise PackageIntegrityError("PACKAGE_INVALID")
    if not callable(namespace.get("execute_operation")):
        raise PackageIntegrityError("PACKAGE_INVALID")
    return namespace


def validate_loader_source(source: bytes) -> bytes:
    if not isinstance(source, bytes) or not source or len(source) > MAX_LOADER_SOURCE_BYTES:
        raise PackageIntegrityError("PACKAGE_INVALID")
    try:
        compile(source.decode("ascii", "strict"), "<fixed-locator-loader>", "exec", dont_inherit=True)
    except (SyntaxError, UnicodeDecodeError, TypeError, ValueError) as error:
        raise PackageIntegrityError("PACKAGE_INVALID") from error
    return source


def build_fixed_loader_source() -> bytes:
    source = (
        "import base64 as _b64\n"
        "import zlib as _zlib\n"
        "_p=_zlib.decompress(_b64.urlsafe_b64decode("
        + repr(CANONICAL_LOCATOR_PACKAGE_B64)
        + "+'==='),-15)\n"
        "_g={'__name__':"
        + repr(FIXED_LOCATOR_NAMESPACE)
        + ",'__file__':"
        + repr(CANONICAL_LOCATOR_PATH)
        + "}\n"
        "exec(compile(_p,"
        + repr(CANONICAL_LOCATOR_PATH)
        + ",'exec',dont_inherit=True),_g,_g)\n"
    ).encode("ascii", "strict")
    return validate_loader_source(source)


FIXED_LOADER_SOURCE = build_fixed_loader_source()
FIXED_LOADER_COMMITMENT = _bytes_commitment("fixed-loader", FIXED_LOADER_SOURCE)


# ---------------------------------------------------------------------------
# Authenticated frames and strict private control schemas.

PROTOCOL_VERSION = 1
FRAME_FLAGS = 0
DIRECTION_LOCAL_TO_REMOTE = 1
DIRECTION_REMOTE_TO_LOCAL = 2
MESSAGE_BOOT = 1
MESSAGE_READY = 2
MESSAGE_DISCOVERY = 3
MESSAGE_PROCEED = 4
MESSAGE_ABORT = 5
MESSAGE_RESULT = 6
MESSAGE_VALUES = frozenset(
    {
        MESSAGE_BOOT,
        MESSAGE_READY,
        MESSAGE_DISCOVERY,
        MESSAGE_PROCEED,
        MESSAGE_ABORT,
        MESSAGE_RESULT,
    }
)
AUTH_FRAME_MAGIC = b"SWZFRM01"
AUTH_FRAME_HEADER_STRUCT = struct.Struct("!8sBBBBQ32s16sI")
assert AUTH_FRAME_HEADER_STRUCT.size == AUTH_FRAME_HEADER_BYTES
BOOT_FIELDS = (
    "type",
    "version",
    "schema",
    "barrier_utc",
    "image_ref",
    "recovery_host_platform",
    "container_identity",
    "volume_identity",
    "container_commitment",
    "volume_commitment",
    "runner_commitment",
    "locator_path",
    "locator_revision",
    "locator_blob",
    "locator_source_commitment",
    "locator_package_commitment",
)
CONTROL_FIELDS = {
    "READY": ("type", "version", "barrier_utc"),
    "DISCOVERY": (
        "type",
        "version",
        "execution_row_id",
        "artifact_filename",
        "isolation_state",
        "isolation_commitment",
    ),
    "PROCEED": (
        "type",
        "version",
        "epoch_digest",
        "authority_digest",
        "runner_digest",
        "bundle_digest",
        "barrier_utc",
        "artifact_commitment",
        "isolation_commitment",
        "transition_id",
        "pre_cas_ledger_digest",
        "transition_data_commitment",
        "consumed_record_digest",
        "grant",
    ),
    "ABORT": ("type", "version", "code"),
    "RESULT": ("type", "version", "classification", "result_commitment"),
}


def _validate_discovery_tuple(execution_row_id: Any, artifact_filename: Any) -> tuple[int, str]:
    if type(execution_row_id) is not int or not 0 < execution_row_id <= 0x7FFFFFFFFFFFFFFF:
        raise ProtocolError("DISCOVERY_INVALID")
    if not isinstance(artifact_filename, str):
        raise ProtocolError("DISCOVERY_INVALID")
    encoded = artifact_filename.encode("utf-8", "strict")
    if (
        not encoded
        or len(encoded) > MAX_FILENAME_BYTES
        or artifact_filename in {".", ".."}
        or "/" in artifact_filename
        or "\\" in artifact_filename
        or any(ord(char) <= 0x1F or ord(char) == 0x7F for char in artifact_filename)
    ):
        raise ProtocolError("DISCOVERY_INVALID")
    return execution_row_id, artifact_filename


def _validate_control(value: Any, expected_type: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError("CONTROL_INVALID")
    message_type = expected_type or value.get("type")
    if message_type not in CONTROL_FIELDS:
        raise ProtocolError("CONTROL_INVALID")
    if tuple(value.keys()) != CONTROL_FIELDS[message_type]:
        raise ProtocolError("CONTROL_INVALID")
    if value.get("type") != message_type or value.get("version") != 1:
        raise ProtocolError("CONTROL_INVALID")
    if message_type == "READY":
        validate_barrier_utc(value["barrier_utc"])
    elif message_type == "DISCOVERY":
        _validate_discovery_tuple(
            value["execution_row_id"],
            value["artifact_filename"],
        )
        if value["isolation_state"] != "PASS" or not _is_commitment(value["isolation_commitment"]):
            raise ProtocolError("DISCOVERY_INVALID")
    elif message_type == "PROCEED":
        for name in (
            "epoch_digest",
            "authority_digest",
            "runner_digest",
            "bundle_digest",
            "artifact_commitment",
            "isolation_commitment",
            "pre_cas_ledger_digest",
            "transition_data_commitment",
            "consumed_record_digest",
        ):
            if not _is_commitment(value[name]):
                raise ProtocolError("CONTROL_INVALID")
        validate_barrier_utc(value["barrier_utc"])
        if not isinstance(value["transition_id"], str) or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
            value["transition_id"],
            re.ASCII,
        ) is None:
            raise ProtocolError("CONTROL_INVALID")
        if not isinstance(value["grant"], str):
            raise ProtocolError("CONTROL_INVALID")
        try:
            raw = base64.urlsafe_b64decode(value["grant"] + "===")
        except (ValueError, TypeError):
            raise ProtocolError("CONTROL_INVALID")
        if (
            len(raw) != 32
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value["grant"]
        ):
            raise ProtocolError("CONTROL_INVALID")
    elif message_type == "ABORT":
        try:
            RunnerControlCode(value["code"])
        except (TypeError, ValueError) as error:
            raise ProtocolError("CONTROL_INVALID") from error
    elif message_type == "RESULT":
        try:
            ResultClassification(value["classification"])
        except (TypeError, ValueError) as error:
            raise ProtocolError("CONTROL_INVALID") from error
        if not _is_commitment(value["result_commitment"]):
            raise ProtocolError("CONTROL_INVALID")
    return value


def encode_control(value: Mapping[str, Any]) -> bytes:
    validated = _validate_control(dict(value))
    return _canonical_json(validated, limit=MAX_CONTROL_PAYLOAD_BYTES)


def decode_control(payload: bytes, expected_type: str | None = None) -> dict[str, Any]:
    value = _parse_canonical_json(payload, limit=MAX_CONTROL_PAYLOAD_BYTES)
    return _validate_control(value, expected_type)


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedFrame:
    direction: int
    message: int
    sequence: int
    session_nonce: bytes = field(repr=False)
    frame_nonce: bytes = field(repr=False)
    payload: bytes

    def __repr__(self) -> str:
        return (
            "AuthenticatedFrame("
            f"direction={self.direction}, message={self.message}, "
            f"sequence={self.sequence}, payload_bytes={len(self.payload)}, "
            "session_nonce=opaque, frame_nonce=opaque)"
        )


def _validate_key(value: Any) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32 or not any(value):
        raise ProtocolError("FRAME_INVALID")
    return value


def _validate_nonce(value: Any, size: int) -> bytes:
    if not isinstance(value, bytes) or len(value) != size or not any(value):
        raise ProtocolError("FRAME_INVALID")
    return value


def encode_authenticated_frame(
    key: bytes,
    direction: int,
    message: int,
    sequence: int,
    session_nonce: bytes,
    payload: bytes,
    *,
    frame_nonce: bytes,
) -> bytes:
    _validate_key(key)
    _validate_nonce(session_nonce, 32)
    _validate_nonce(frame_nonce, 16)
    if direction not in {DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL}:
        raise ProtocolError("FRAME_INVALID")
    if message not in MESSAGE_VALUES or type(sequence) is not int or not 0 < sequence < 2**64:
        raise ProtocolError("FRAME_INVALID")
    if not isinstance(payload, bytes) or len(payload) > MAX_AUTH_PAYLOAD_BYTES:
        raise ProtocolError("FRAME_INVALID")
    header = AUTH_FRAME_HEADER_STRUCT.pack(
        AUTH_FRAME_MAGIC,
        PROTOCOL_VERSION,
        direction,
        message,
        FRAME_FLAGS,
        sequence,
        session_nonce,
        frame_nonce,
        len(payload),
    )
    return header + payload + hmac.new(key, header + payload, hashlib.sha256).digest()


def decode_authenticated_frame(key: bytes, frame: bytes) -> AuthenticatedFrame:
    _validate_key(key)
    if not isinstance(frame, bytes) or len(frame) < AUTH_FRAME_OVERHEAD:
        raise ProtocolError("FRAME_INVALID")
    try:
        header = frame[:AUTH_FRAME_HEADER_BYTES]
        (
            magic,
            version,
            direction,
            message,
            flags,
            sequence,
            session_nonce,
            frame_nonce,
            payload_length,
        ) = AUTH_FRAME_HEADER_STRUCT.unpack(header)
    except struct.error as error:
        raise ProtocolError("FRAME_INVALID") from error
    if (
        magic != AUTH_FRAME_MAGIC
        or version != PROTOCOL_VERSION
        or direction not in {DIRECTION_LOCAL_TO_REMOTE, DIRECTION_REMOTE_TO_LOCAL}
        or message not in MESSAGE_VALUES
        or flags != FRAME_FLAGS
        or type(sequence) is not int
        or sequence == 0
        or payload_length > MAX_AUTH_PAYLOAD_BYTES
        or len(frame) != AUTH_FRAME_OVERHEAD + payload_length
    ):
        raise ProtocolError("FRAME_INVALID")
    _validate_nonce(session_nonce, 32)
    _validate_nonce(frame_nonce, 16)
    payload = frame[AUTH_FRAME_HEADER_BYTES : AUTH_FRAME_HEADER_BYTES + payload_length]
    expected = hmac.new(key, header + payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, frame[-AUTH_FRAME_TAG_BYTES:]):
        raise ProtocolError("FRAME_INVALID")
    return AuthenticatedFrame(
        direction,
        message,
        sequence,
        session_nonce,
        frame_nonce,
        payload,
    )


class SessionBudget:
    """Exact frame-count and total-byte admission for one authenticated session."""

    def __init__(self) -> None:
        self.frames = 0
        self.bytes = 0
        self._nonces: set[bytes] = set()

    def add(self, frame: AuthenticatedFrame | bytes) -> None:
        if isinstance(frame, bytes):
            size = len(frame)
            nonce = None
        else:
            size = AUTH_FRAME_OVERHEAD + len(frame.payload)
            nonce = frame.frame_nonce
        if size > MAX_AUTH_FRAME_BYTES or self.frames >= MAX_SESSION_FRAMES:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        if self.bytes + size > MAX_SESSION_BYTES:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        if nonce is not None:
            if nonce in self._nonces:
                raise ProtocolError("FRAME_INVALID")
            self._nonces.add(nonce)
        self.frames += 1
        self.bytes += size

    def charge(self, size: int) -> None:
        if type(size) is not int or size < 0:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        if size > MAX_AUTH_FRAME_BYTES or self.frames >= MAX_SESSION_FRAMES:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        if self.bytes + size > MAX_SESSION_BYTES:
            raise ProtocolError("SESSION_LIMIT_EXCEEDED")
        self.frames += 1
        self.bytes += size


class BoundedCapture:
    def __init__(self, limit: int):
        if type(limit) is not int or limit < 0:
            raise ValueError("capture limit")
        self.limit = limit
        self.data = bytearray()
        self.seen = 0
        self.overflow = False

    def append(self, payload: bytes) -> None:
        if not isinstance(payload, bytes):
            raise TypeError("capture payload")
        self.seen += len(payload)
        if self.seen > self.limit:
            self.overflow = True
            return
        self.data.extend(payload)


class CaptureSet:
    """Separate stream bounds plus the exact combined capture ceiling."""

    def __init__(self) -> None:
        self.stdout = BoundedCapture(MAX_STDOUT_CAPTURE_BYTES)
        self.stderr = BoundedCapture(MAX_STDERR_CAPTURE_BYTES)
        self.combined_seen = 0
        self.combined_overflow = False

    def append(self, channel: str, payload: bytes) -> None:
        if channel == "stdout":
            self.stdout.append(payload)
        elif channel == "stderr":
            self.stderr.append(payload)
        else:
            raise BridgeError("CAPTURE_INVALID")
        self.combined_seen += len(payload)
        if self.combined_seen > MAX_COMBINED_CAPTURE_BYTES:
            self.combined_overflow = True


def validate_reader_chunk(payload: bytes) -> bytes:
    if not isinstance(payload, bytes) or len(payload) > READER_CHUNK_BYTES:
        raise BridgeError("READER_CHUNK_LIMIT_EXCEEDED")
    return payload


class EventQueueBudget:
    """A deterministic offline capacity proof for the 16-entry reader queue."""

    def __init__(self) -> None:
        self._items: list[Any] = []

    def put(self, value: Any) -> None:
        if len(self._items) >= EVENT_QUEUE_MAX_ENTRIES:
            raise BridgeError("EVENT_QUEUE_LIMIT_EXCEEDED")
        self._items.append(value)

    def get(self) -> Any:
        if not self._items:
            raise BridgeError("EVENT_QUEUE_EMPTY")
        return self._items.pop(0)

    @property
    def size(self) -> int:
        return len(self._items)


class MemoryBudget:
    def __init__(self, limit: int = MAX_MEMORY_BYTES):
        self.limit = limit
        self.used = 0

    def reserve(self, size: int) -> None:
        if type(size) is not int or size < 0 or self.used + size > self.limit:
            raise BridgeError("MEMORY_LIMIT_EXCEEDED")
        self.used += size


# ---------------------------------------------------------------------------
# Domain plan, key graph, and BOOT causality.

@dataclass(frozen=True, slots=True, repr=False)
class RecoveryPlanV1:
    epoch_ref: str
    authority_ref: str
    barrier_utc: str
    container_identity: str
    volume_identity: str
    runner_identity: str
    salt: str
    recovery_host_platform: str = "linux"
    image_ref: str = "postgres:17-alpine"

    def __post_init__(self) -> None:
        _validate_ref(self.epoch_ref, "epoch_ref")
        _validate_ref(self.authority_ref, "authority_ref")
        validate_barrier_utc(self.barrier_utc)
        _validate_private_text(self.container_identity, "container_identity")
        _validate_private_text(self.volume_identity, "volume_identity")
        _validate_private_text(self.runner_identity, "runner_identity")
        _validate_private_text(self.salt, "salt")
        if self.recovery_host_platform != "linux" or self.image_ref != "postgres:17-alpine":
            raise BridgeError("PLATFORM_UNSUPPORTED")

    @property
    def container_commitment(self) -> str:
        return _commitment("container-identity", self.container_identity)

    @property
    def volume_commitment(self) -> str:
        return _commitment("volume-identity", self.volume_identity)

    @property
    def runner_commitment(self) -> str:
        return _commitment("runner-identity", self.runner_identity)

    def __repr__(self) -> str:
        return (
            "RecoveryPlanV1("
            f"epoch_ref={self.epoch_ref!r}, authority_ref={self.authority_ref!r}, "
            "private_identities=opaque, image_ref='postgres:17-alpine')"
        )


def build_boot_payload(plan: RecoveryPlanV1, runner_commitment: str | None = None) -> dict[str, Any]:
    selected_runner = runner_commitment or plan.runner_commitment
    if not _is_commitment(selected_runner):
        raise ProtocolError("BOOT_INVALID")
    payload = {
        "type": "BOOT",
        "version": 1,
        "schema": "recovery-plan-v1",
        "barrier_utc": plan.barrier_utc,
        "image_ref": plan.image_ref,
        "recovery_host_platform": plan.recovery_host_platform,
        "container_identity": plan.container_identity,
        "volume_identity": plan.volume_identity,
        "container_commitment": plan.container_commitment,
        "volume_commitment": plan.volume_commitment,
        "runner_commitment": selected_runner,
        "locator_path": CANONICAL_LOCATOR_PATH,
        "locator_revision": CANONICAL_REVISION,
        "locator_blob": CANONICAL_LOCATOR_BLOB,
        "locator_source_commitment": CANONICAL_LOCATOR_SOURCE_COMMITMENT,
        "locator_package_commitment": CANONICAL_LOCATOR_PACKAGE_BINDING,
    }
    if tuple(payload) != BOOT_FIELDS:
        raise ProtocolError("BOOT_INVALID")
    return payload


def validate_boot_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    if tuple(payload) != BOOT_FIELDS:
        raise ProtocolError("BOOT_INVALID")
    if "image_id" in payload or "image_commitment" in payload:
        raise ProtocolError("BOOT_INVALID")
    if payload["type"] != "BOOT" or payload["version"] != 1 or payload["schema"] != "recovery-plan-v1":
        raise ProtocolError("BOOT_INVALID")
    validate_barrier_utc(payload["barrier_utc"])
    if payload["image_ref"] != "postgres:17-alpine" or payload["recovery_host_platform"] != "linux":
        raise ProtocolError("BOOT_INVALID")
    for name in ("container_commitment", "volume_commitment", "runner_commitment", "locator_package_commitment"):
        if not _is_commitment(payload[name]):
            raise ProtocolError("BOOT_INVALID")
    if payload["locator_path"] != CANONICAL_LOCATOR_PATH:
        raise ProtocolError("BOOT_INVALID")
    if payload["locator_revision"] != CANONICAL_REVISION or payload["locator_blob"] != CANONICAL_LOCATOR_BLOB:
        raise ProtocolError("BOOT_INVALID")
    if payload["locator_source_commitment"] != CANONICAL_LOCATOR_SOURCE_COMMITMENT:
        raise ProtocolError("BOOT_INVALID")
    _validate_private_text(payload["container_identity"], "container_identity")
    _validate_private_text(payload["volume_identity"], "volume_identity")
    return payload


@dataclass(frozen=True, slots=True, repr=False)
class BridgeKeyGraph:
    epoch_ref: str
    authority_ref: str
    runner_identity: str = field(repr=False)
    n_remote: bytes = field(repr=False)
    n_local: bytes = field(repr=False)
    n_session: bytes = field(repr=False)
    bootstrap_seed: bytes = field(repr=False)
    epoch_commitment: str
    authority_commitment: str
    runner_commitment: str
    bundle_commitment: str
    barrier_utc: str = field(repr=False)
    barrier_commitment: str = field(repr=False)
    isolation_commitment: str | None = field(default=None, repr=False)
    k_boot: bytes = field(repr=False, default=b"")
    k_session: bytes = field(repr=False, default=b"")
    k_proceed: bytes = field(repr=False, default=b"")

    def __repr__(self) -> str:
        return (
            "BridgeKeyGraph("
            f"epoch_ref={self.epoch_ref!r}, authority_ref={self.authority_ref!r}, "
            "session_bound=True, secrets=opaque)"
        )

    def with_isolation(self, isolation_commitment: str) -> "BridgeKeyGraph":
        if not _is_commitment(isolation_commitment):
            raise ProtocolError("CONTROL_INVALID")
        k_proceed = _derive_key(
            self.bootstrap_seed,
            "K_proceed.v1",
            self.n_remote,
            self.n_local,
            self.n_session,
            self.epoch_commitment,
            self.authority_commitment,
            self.runner_commitment,
            self.bundle_commitment,
            self.barrier_commitment,
            isolation_commitment,
        )
        return dataclasses.replace(
            self,
            isolation_commitment=isolation_commitment,
            k_proceed=k_proceed,
        )


def _derive_key(seed: bytes, domain: str, *parts: str | bytes) -> bytes:
    _validate_key(seed)
    return hmac.new(seed, _lp(domain, *parts), hashlib.sha256).digest()


def derive_local_key_graph(
    *,
    spool_hmac_key: str,
    salt: str,
    epoch_ref: str,
    authority_ref: str,
    runner_identity: str,
    n_remote: bytes,
    n_local: bytes,
    barrier_utc: str,
    record_commitment: str,
    runner_commitment: str | None = None,
    authority_commitment: str | None = None,
    bundle_commitment: str = CANONICAL_LOCATOR_PACKAGE_BINDING,
) -> BridgeKeyGraph:
    validate_barrier_utc(barrier_utc)
    key = spool_hmac_key.encode("utf-8", "strict")
    if not key:
        raise BridgeError("STORE_STATE_INVALID")
    _validate_key(key)
    _validate_nonce(n_remote, 32)
    _validate_nonce(n_local, 32)
    for value in (record_commitment, bundle_commitment):
        if not _is_commitment(value):
            raise BridgeError("STORE_STATE_INVALID")
    selected_runner = runner_commitment or _commitment("runner", runner_identity)
    selected_authority = authority_commitment or _commitment("authority", authority_ref)
    if not _is_commitment(selected_runner) or not _is_commitment(selected_authority):
        raise BridgeError("STORE_STATE_INVALID")
    barrier_commitment = _bytes_commitment("barrier", barrier_utc.encode("ascii"))
    seed = hmac.new(
        key,
        _lp(
            "K_bridge_root.v1",
            salt,
            epoch_ref,
            authority_ref,
            record_commitment,
            selected_authority,
            selected_runner,
            bundle_commitment,
            barrier_commitment,
        ),
        hashlib.sha256,
    ).digest()
    n_session = _derive_key(
        seed,
        "N_session.v1",
        n_remote,
        n_local,
        record_commitment,
        selected_authority,
        selected_runner,
        bundle_commitment,
    )
    k_boot = _derive_key(
        seed,
        "K_boot.v1",
        n_remote,
        n_local,
        n_session,
        record_commitment,
        selected_authority,
        selected_runner,
        bundle_commitment,
    )
    k_session = _derive_key(
        seed,
        "K_session.v1",
        n_remote,
        n_local,
        n_session,
        record_commitment,
        selected_authority,
        selected_runner,
        bundle_commitment,
        barrier_commitment,
    )
    return BridgeKeyGraph(
        epoch_ref=epoch_ref,
        authority_ref=authority_ref,
        runner_identity=runner_identity,
        n_remote=n_remote,
        n_local=n_local,
        n_session=n_session,
        bootstrap_seed=seed,
        epoch_commitment=record_commitment,
        authority_commitment=selected_authority,
        runner_commitment=selected_runner,
        bundle_commitment=bundle_commitment,
        barrier_utc=barrier_utc,
        barrier_commitment=barrier_commitment,
        k_boot=k_boot,
        k_session=k_session,
        k_proceed=_derive_key(
            seed,
            "K_proceed.v1",
            n_remote,
            n_local,
            n_session,
            record_commitment,
            selected_authority,
            selected_runner,
            bundle_commitment,
            barrier_commitment,
            "NO_ISOLATION",
        ),
    )


# ---------------------------------------------------------------------------
# Process/read finality and private artifact continuity.

EXIT_SUCCESS = 0
EXIT_RUNNER_ABORT = 65


@dataclass(frozen=True, slots=True, repr=False)
class ProcessTerminalEvidence:
    exit_code: int | None
    natural_exit: bool
    stdout_eof: bool
    stderr_eof: bool
    stdout_trailing_bytes: int
    stderr_bytes: int
    stdout_overflow: bool
    stderr_overflow: bool
    termination_uncertain: bool

    def __repr__(self) -> str:
        return (
            "ProcessTerminalEvidence("
            f"exit_code={self.exit_code!r}, natural_exit={self.natural_exit!r}, "
            f"stdout_eof={self.stdout_eof!r}, stderr_eof={self.stderr_eof!r}, "
            f"stdout_trailing_bytes={self.stdout_trailing_bytes}, "
            f"stderr_bytes={self.stderr_bytes}, "
            f"stdout_overflow={self.stdout_overflow!r}, stderr_overflow={self.stderr_overflow!r}, "
            f"termination_uncertain={self.termination_uncertain!r})"
        )


class ProcessSupervisor:
    @staticmethod
    def finality_error(
        evidence: ProcessTerminalEvidence,
        *,
        expected_exit: int = EXIT_SUCCESS,
    ) -> str | None:
        if evidence.stdout_overflow or evidence.stderr_overflow:
            return "PROCESS_CAPTURE_OVERFLOW"
        if evidence.stdout_trailing_bytes:
            return "PROCESS_TRAILING_OUTPUT"
        if evidence.stderr_bytes:
            return "PROCESS_STDERR_FORBIDDEN"
        if not evidence.stdout_eof or not evidence.stderr_eof:
            return "PROCESS_TERMINATION_UNCERTAIN"
        if evidence.termination_uncertain or not evidence.natural_exit:
            return "PROCESS_TERMINATION_UNCERTAIN"
        if evidence.exit_code != expected_exit:
            return "PROCESS_EXIT_NONZERO"
        return None


class QualifiedArtifact:
    """One no-follow-qualified object kept across read and restore."""

    def __init__(self, execution_row_id: int, artifact_filename: str, content: bytes):
        _validate_discovery_tuple(execution_row_id, artifact_filename)
        if not isinstance(content, bytes) or not content:
            raise BridgeError("ARTIFACT_INVALID")
        self.execution_row_id = execution_row_id
        self.artifact_filename = artifact_filename
        self._content = content
        self.handle_identity = object()
        self.opened_no_follow = True
        self.fstat_calls = 0
        self.read_calls = 0
        self.restore_calls = 0
        self.reopen_attempts = 0
        self.closed = False

    def fstat(self) -> tuple[int, int]:
        if self.closed:
            raise BridgeError("ARTIFACT_INVALID")
        self.fstat_calls += 1
        return id(self.handle_identity), len(self._content)

    def read(self) -> bytes:
        if self.closed:
            raise BridgeError("ARTIFACT_INVALID")
        self.read_calls += 1
        return self._content

    def restore(self) -> bytes:
        if self.closed:
            raise BridgeError("ARTIFACT_INVALID")
        self.restore_calls += 1
        return self._content

    def reopen(self) -> None:
        self.reopen_attempts += 1
        raise BridgeError("ARTIFACT_REOPEN_FORBIDDEN")

    def close(self) -> None:
        self.closed = True


class SyntheticArtifactProvider:
    def __init__(self, content: bytes = b"synthetic-qualified-artifact\n"):
        self.content = content
        self.open_calls = 0
        self.last_artifact: QualifiedArtifact | None = None

    def open_no_follow(self, execution_row_id: int, artifact_filename: str) -> QualifiedArtifact:
        self.open_calls += 1
        artifact = QualifiedArtifact(execution_row_id, artifact_filename, self.content)
        self.last_artifact = artifact
        return artifact


@dataclass(frozen=True, slots=True, repr=False)
class ImageResource:
    image_id: str = field(repr=False)
    container_identity: str = field(repr=False)
    volume_identity: str = field(repr=False)
    target_id: str = field(repr=False)
    volume_id: str = field(repr=False)
    owner: str = field(repr=False)
    cleaned: bool = field(default=False, repr=False)

    def __repr__(self) -> str:
        return "ImageResource(image_id=opaque,target=opaque,volume=opaque)"


class SyntheticImageSource:
    """A deterministic post-BOOT image/target fixture; never calls Docker."""

    def __init__(
        self,
        *,
        image_id: str = "sha256:" + ("a" * 64),
        mode: str = "success",
    ):
        self.image_id = image_id
        self.mode = mode
        self.inspect_calls = 0
        self.pull_calls = 0
        self.create_calls = 0
        self.readback_calls = 0
        self.cleanup_calls = 0
        self.resource: ImageResource | None = None

    def inspect(self, image_ref: str) -> str:
        self.inspect_calls += 1
        if image_ref != "postgres:17-alpine" or self.mode == "inspect-fail":
            raise BridgeError("IMAGE_INSPECTION_FAILED")
        return _validate_image_id(self.image_id)

    def pull(self, image_ref: str) -> None:
        self.pull_calls += 1
        raise BridgeError("IMAGE_PROFILE_INVALID")

    def create_disposable(self, image_id: str, container_identity: str, volume_identity: str) -> ImageResource:
        if self.resource is not None:
            raise BridgeError("RESOURCE_COLLISION")
        if self.mode == "collision":
            raise BridgeError("RESOURCE_COLLISION")
        self.create_calls += 1
        resource = ImageResource(
            image_id=image_id,
            container_identity=container_identity,
            volume_identity=volume_identity,
            target_id="run-owned-target-001",
            volume_id="run-owned-volume-001",
            owner="run-343",
        )
        self.resource = resource
        if self.mode == "create-fail":
            raise BridgeError("RESOURCE_CREATE_FAILED")
        return resource

    def readback_isolation(self, resource: ImageResource) -> Mapping[str, Any]:
        self.readback_calls += 1
        if self.mode == "isolation-fail":
            raise BridgeError("ISOLATION_FAILED")
        if self.resource is not resource:
            raise BridgeError("ISOLATION_FAILED")
        return {
            "schema": "bridge-isolation-proof.v1",
            "image_id": resource.image_id,
            "target_id": resource.target_id,
            "volume_id": resource.volume_id,
            "owner": resource.owner,
            "effective_image_id": resource.image_id,
            "effective_isolation": True,
        }

    def cleanup_exact(self, resource: ImageResource) -> None:
        self.cleanup_calls += 1
        if self.resource is not resource or resource.owner != "run-343":
            raise BridgeError("CLEANUP_UNPROVEN")
        self.resource = dataclasses.replace(resource, cleaned=True)


@dataclass(frozen=True, slots=True, repr=False)
class ImageAdmission:
    image_commitment: str
    isolation_commitment: str
    resource: ImageResource = field(repr=False)
    proof: Mapping[str, Any] = field(repr=False)

    def __repr__(self) -> str:
        return "ImageAdmission(image_commitment=opaque,isolation_commitment=opaque)"


def _admit_image(
    plan: RecoveryPlanV1,
    image_source: SyntheticImageSource,
) -> ImageAdmission:
    image_id = image_source.inspect(plan.image_ref)
    image_commitment = _commitment("immutable-image", image_id)
    resource = image_source.create_disposable(
        image_id,
        plan.container_identity,
        plan.volume_identity,
    )
    proof = dict(image_source.readback_isolation(resource))
    if (
        proof.get("effective_isolation") is not True
        or proof.get("effective_image_id") != image_id
        or proof.get("image_id") != image_id
        or proof.get("owner") != "run-343"
    ):
        raise BridgeError("ISOLATION_FAILED")
    proof_bytes = _canonical_json(
        {
            "schema": proof["schema"],
            "image_commitment": image_commitment,
            "effective_isolation": proof["effective_isolation"],
            "effective_image_commitment": _commitment(
                "immutable-image", proof["effective_image_id"]
            ),
            "target_commitment": _commitment("run-owned-target", proof["target_id"]),
            "volume_commitment": _commitment("run-owned-volume", proof["volume_id"]),
        },
        limit=MAX_CONTROL_PAYLOAD_BYTES,
    )
    isolation_commitment = _bytes_commitment("isolation-proof", proof_bytes)
    return ImageAdmission(image_commitment, isolation_commitment, resource, proof)


@dataclass(frozen=True, slots=True, repr=False)
class LocatorFacts:
    classification: str
    schedule_id: int | None
    execution_id: int | None
    execution_created_at: str | None
    artifact_filename: str | None
    operation_counts: Mapping[str, int]

    def __repr__(self) -> str:
        return (
            "LocatorFacts("
            f"classification={self.classification!r}, "
            f"operation_counts={dict(self.operation_counts)!r}, private=opaque)"
        )


class _ReadablePipe:
    def __init__(self):
        self._chunks: queue.Queue[bytes | None] = queue.Queue()
        self._buffer = bytearray()
        self._closed = False

    def feed(self, payload: bytes) -> None:
        if not self._closed:
            self._chunks.put(payload)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._chunks.put(None)

    def read(self, length: int = -1) -> bytes:
        while not self._buffer and not self._closed:
            chunk = self._chunks.get()
            if chunk is None:
                self._closed = True
                break
            self._buffer.extend(chunk)
        if length is None or length < 0:
            length = len(self._buffer)
        result = bytes(self._buffer[:length])
        del self._buffer[:length]
        return result


class _LocatorStdin:
    def __init__(self, process: "_FixedLocatorProcess"):
        self.process = process
        self.closed = False

    def write(self, payload: bytes) -> int:
        if self.closed:
            raise BrokenPipeError("closed")
        self.process.accept(payload)
        return len(payload)

    def flush(self) -> None:
        if self.closed:
            raise BrokenPipeError("closed")

    def close(self) -> None:
        self.closed = True


class _FixedLocatorProcess:
    def __init__(self):
        self.stdin = _LocatorStdin(self)
        self.stdout = _ReadablePipe()
        self.stderr = _ReadablePipe()
        self.returncode: int | None = None
        self._input = bytearray()
        self._ready = False
        self._result = False
        self._lock = threading.Lock()

    def accept(self, payload: bytes) -> None:
        with self._lock:
            self._input.extend(payload)
            if not self._ready and b"\\echo SPLQ_PUBLIC_READY_V1\n" in self._input:
                self._ready = True
                self.stdout.feed(b"SPLQ_PUBLIC_READY_V1\n")
            if self._ready and not self._result and b"\\q\n" in self._input:
                self._result = True
                result = {
                    "schedule_count": 1,
                    "schedule_id": 23,
                    "execution_count": 1,
                    "execution_id": 47,
                    "execution_created_at": "2026-09-04T00:00:00.000000Z",
                    "filename": "synthetic-backup-001.dump",
                }
                self.stdout.feed(
                    (json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8")
                )
                self.stdout.close()
                self.stderr.close()
                self.returncode = 0

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            self.stdout.close()
            self.stderr.close()
            self.returncode = 1
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 1
        self.stdout.close()
        self.stderr.close()

    def kill(self) -> None:
        self.terminate()


def fixed_process_factory() -> _FixedLocatorProcess:
    return _FixedLocatorProcess()


def fixed_clock() -> float:
    return time.monotonic()


def fixed_event_queue_factory() -> queue.Queue[tuple[str, Any]]:
    return queue.Queue(maxsize=16)


def execute_canonical_locator_once(barrier_utc: str) -> LocatorFacts:
    """Invoke exactly one fixed packaged locator operation."""

    validate_barrier_utc(barrier_utc)
    namespace = compile_canonical_locator_namespace()
    outcome = namespace["execute_operation"](
        barrier_utc,
        process_factory=fixed_process_factory,
        clock=fixed_clock,
        event_queue_factory=fixed_event_queue_factory,
    )
    counts = getattr(outcome, "counts", None)
    public_counts = {}
    if counts is not None:
        public_counts = {
            "docker_execs": int(getattr(counts, "docker_execs", 0)),
            "shell_wrappers": int(getattr(counts, "shell_wrappers", 0)),
            "psql_sessions": int(getattr(counts, "psql_sessions", 0)),
            "logical_selects": int(getattr(counts, "logical_selects", 0)),
            "phase1_writes": int(getattr(counts, "phase1_writes", 0)),
            "phase2_writes": int(getattr(counts, "phase2_writes", 0)),
        }
    if getattr(outcome, "classification", None) != "EXACTLY_ONE":
        classification = getattr(outcome, "classification", "QUERY_FAILED")
        if classification == "MULTIPLE_ROW_MATCH":
            raise BridgeError("LOCATOR_AMBIGUOUS")
        raise BridgeError("LOCATOR_NOT_FOUND")
    row_id = getattr(outcome, "execution_id", None)
    filename = getattr(outcome, "filename", None)
    timestamp = getattr(outcome, "execution_created_at", None)
    if (
        type(row_id) is not int
        or not isinstance(filename, str)
        or not isinstance(timestamp, str)
    ):
        raise BridgeError("LOCATOR_FAILED")
    _validate_discovery_tuple(row_id, filename)
    validate_barrier_utc(timestamp)
    return LocatorFacts(
        "EXACTLY_ONE",
        getattr(outcome, "schedule_id", None),
        row_id,
        timestamp,
        filename,
        public_counts,
    )


# ---------------------------------------------------------------------------
# Fixed remote-side state and local controller/store integration.

@dataclass(frozen=True, slots=True, repr=False)
class Discovery:
    execution_row_id: int
    artifact_filename: str
    execution_created_at: str
    isolation_commitment: str
    isolation_state: str
    image_admission: ImageAdmission = field(repr=False)
    artifact: QualifiedArtifact = field(repr=False)

    def wire_payload(self) -> dict[str, Any]:
        value = {
            "type": "DISCOVERY",
            "version": 1,
            "execution_row_id": self.execution_row_id,
            "artifact_filename": self.artifact_filename,
            "isolation_state": self.isolation_state,
            "isolation_commitment": self.isolation_commitment,
        }
        decode_control(encode_control(value), "DISCOVERY")
        return value

    def __repr__(self) -> str:
        return (
            "Discovery(execution_row_id=opaque,artifact_filename=opaque,"
            "isolation=opaque)"
        )


class FixedRemoteAgent:
    """Synthetic fixed agent representing the admitted repository-owned payload."""

    def __init__(
        self,
        plan: RecoveryPlanV1,
        *,
        image_source: SyntheticImageSource,
        artifact_source: SyntheticArtifactProvider,
        counters: "BridgeCounters",
    ):
        self.plan = plan
        self.image_source = image_source
        self.artifact_source = artifact_source
        self.counters = counters
        self.admission: ImageAdmission | None = None
        self.discovery: Discovery | None = None
        self._cleaned = False
        self._proceed_count = 0

    def boot(self, runner_commitment: str) -> dict[str, Any]:
        value = build_boot_payload(self.plan, runner_commitment)
        validate_boot_payload(value)
        self.counters.boot_messages += 1
        return value

    def ready(self) -> dict[str, Any]:
        value = {
            "type": "READY",
            "version": 1,
            "barrier_utc": self.plan.barrier_utc,
        }
        decode_control(encode_control(value), "READY")
        self.counters.ready_messages += 1
        return value

    def discover(self) -> Discovery:
        if self.discovery is not None:
            raise BridgeError("DISCOVERY_INVALID")
        try:
            self.admission = _admit_image(self.plan, self.image_source)
            self.counters.image_inspections = self.image_source.inspect_calls
            self.counters.target_creations = self.image_source.create_calls
            self.counters.isolation_readbacks = self.image_source.readback_calls
            facts = execute_canonical_locator_once(self.plan.barrier_utc)
            if facts.classification != "EXACTLY_ONE" or facts.artifact_filename is None:
                raise BridgeError("LOCATOR_NOT_FOUND")
            artifact = self.artifact_source.open_no_follow(
                facts.execution_id,
                facts.artifact_filename,
            )
            artifact.fstat()
            artifact.read()
            self.discovery = Discovery(
                execution_row_id=facts.execution_id,
                artifact_filename=facts.artifact_filename,
                execution_created_at=facts.execution_created_at or "",
                isolation_commitment=self.admission.isolation_commitment,
                isolation_state="PASS",
                image_admission=self.admission,
                artifact=artifact,
            )
            self.counters.artifact_open_calls = self.artifact_source.open_calls
            return self.discovery
        except Exception:
            self.counters.image_inspections = self.image_source.inspect_calls
            self.counters.target_creations = self.image_source.create_calls
            self.counters.isolation_readbacks = self.image_source.readback_calls
            self.cleanup()
            raise

    def accept_proceed(
        self,
        graph: BridgeKeyGraph,
        proceed_payload: Mapping[str, Any],
        *,
        artifact_commitment: str,
        transition_id: str,
        decision: "DummyDecision",
    ) -> "RemoteResult":
        self._proceed_count += 1
        if self._proceed_count != 1:
            raise BridgeError("PROTOCOL_FAILURE")
        value = decode_control(encode_control(dict(proceed_payload)), "PROCEED")
        if graph.isolation_commitment is None:
            raise BridgeError("PROCEED_INVALID")
        capability = proceed_commitment(
            graph,
            artifact_commitment,
            graph.isolation_commitment,
            transition_id,
            value["pre_cas_ledger_digest"],
            value["transition_data_commitment"],
            value["consumed_record_digest"],
        )
        expected_grant = _grant_token(graph, capability)
        expected_text = base64.urlsafe_b64encode(expected_grant).decode("ascii").rstrip("=")
        if value["grant"] != expected_text:
            raise BridgeError("PROCEED_INVALID")
        if not decision.permitted:
            self.cleanup()
            return RemoteResult(
                ResultClassification.FAILURE.value,
                _commitment("remote-abort", RunnerControlCode.LOCAL_ABORT.value),
                ProcessTerminalEvidence(
                    EXIT_RUNNER_ABORT,
                    True,
                    True,
                    True,
                    0,
                    0,
                    False,
                    False,
                    False,
                ),
                RunnerControlCode.LOCAL_ABORT.value,
            )
        if self.discovery is None:
            raise BridgeError("RESULT_BEFORE_PROCEED")
        self.discovery.artifact.restore()
        self.counters.restore_attempts += 1
        self.cleanup()
        result_commitment = _commitment(
            "remote-result",
            "SUCCESS",
            artifact_commitment,
            graph.isolation_commitment,
            transition_id,
        )
        return RemoteResult(
            ResultClassification.SUCCESS.value,
            result_commitment,
            ProcessTerminalEvidence(
                EXIT_SUCCESS,
                True,
                True,
                True,
                0,
                0,
                False,
                False,
                False,
            ),
            None,
        )

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        if self.admission is None:
            resource = self.image_source.resource
            if resource is not None and not resource.cleaned:
                self.image_source.cleanup_exact(resource)
                self.counters.cleanup_calls += 1
            return
        self.image_source.cleanup_exact(self.admission.resource)
        self.counters.cleanup_calls += 1


@dataclass(frozen=True, slots=True, repr=False)
class RemoteResult:
    classification: str
    result_commitment: str
    terminal_evidence: ProcessTerminalEvidence
    error_code: str | None

    def __repr__(self) -> str:
        return (
            f"RemoteResult(classification={self.classification!r},"
            f"error_code={self.error_code!r},terminal=opaque)"
        )


def proceed_commitment(
    graph: BridgeKeyGraph,
    artifact_commitment: str,
    isolation_commitment: str,
    transition_id: str,
    pre_cas_ledger_digest: str,
    transition_data_commitment: str,
    consumed_record_digest: str,
) -> str:
    if graph.isolation_commitment != isolation_commitment:
        raise ProtocolError("PROCEED_INVALID")
    for value in (
        artifact_commitment,
        isolation_commitment,
        pre_cas_ledger_digest,
        transition_data_commitment,
        consumed_record_digest,
    ):
        if not _is_commitment(value):
            raise ProtocolError("PROCEED_INVALID")
    if not isinstance(transition_id, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
        transition_id,
        re.ASCII,
    ) is None:
        raise ProtocolError("PROCEED_INVALID")
    return _commitment(
        "proceed-capability",
        graph.epoch_commitment,
        graph.authority_commitment,
        graph.runner_commitment,
        graph.bundle_commitment,
        graph.barrier_commitment,
        isolation_commitment,
        artifact_commitment,
        transition_id,
        pre_cas_ledger_digest,
        transition_data_commitment,
        consumed_record_digest,
        graph.k_proceed,
    )


def _grant_token(graph: BridgeKeyGraph, capability: str) -> bytes:
    if not _is_commitment(capability):
        raise ProtocolError("PROCEED_INVALID")
    return hmac.new(
        graph.k_proceed,
        _lp("C_proceed.v1", capability),
        hashlib.sha256,
    ).digest()


def build_restore_transition(
    *,
    epoch_ref: str,
    authority_ref: str,
    runner_commitment: str,
    runner_bundle_commitment: str,
    barrier_utc: str,
    artifact_commitment: str,
    isolation_commitment: str,
    pre_cas_ledger_digest: str,
) -> tuple[dict[str, Any], str, str]:
    validate_barrier_utc(barrier_utc)
    for value in (
        runner_commitment,
        runner_bundle_commitment,
        artifact_commitment,
        isolation_commitment,
        pre_cas_ledger_digest,
    ):
        if not _is_commitment(value):
            raise ProtocolError("STORE_TRANSITION_FAILED")
    base = {
        "schema": "bridge-restore-transition.v1",
        "version": 1,
        "epoch_ref": _validate_ref(epoch_ref, "epoch_ref"),
        "authority_ref": _validate_ref(authority_ref, "authority_ref"),
        "runner_commitment": runner_commitment,
        "runner_bundle_commitment": runner_bundle_commitment,
        "barrier_utc": barrier_utc,
        "artifact_commitment": artifact_commitment,
        "isolation_commitment": isolation_commitment,
        "pre_cas_ledger_digest": pre_cas_ledger_digest,
    }
    transition_id = "bridge-restore-" + hashlib.sha256(
        _canonical_json(base, limit=8192)
    ).hexdigest()[:48]
    transition = dict(base)
    transition["transition_id"] = transition_id
    transition_commitment = _store_bytes_commitment(
        "restore-ledger-transition",
        _canonical_json(transition, limit=8192),
    )
    return transition, transition_id, transition_commitment


@dataclass(slots=True)
class BridgeCounters:
    boot_messages: int = 0
    ready_messages: int = 0
    discovery_messages: int = 0
    bind_calls: int = 0
    reload_calls: int = 0
    epoch_ready_frames: int = 0
    runner_started_frames: int = 0
    cas_attempts: int = 0
    cas_classification_reload_calls: int = 0
    cas_a: int = 0
    cas_b: int = 0
    cas_c: int = 0
    restore_begin_frames: int = 0
    proceed_messages: int = 0
    result_messages: int = 0
    commits: int = 0
    abandon_calls: int = 0
    image_inspections: int = 0
    target_creations: int = 0
    isolation_readbacks: int = 0
    artifact_open_calls: int = 0
    restore_attempts: int = 0
    cleanup_calls: int = 0
    locator_calls: int = 0
    ssh_launches: int = 0
    network_connections: int = 0
    provider_calls: int = 0
    backup_calls: int = 0
    session_bytes: int = 0
    session_frames: int = 0

    def public(self) -> dict[str, int]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True, repr=False)
class DummyDecision:
    permitted: bool
    code: str = RunnerControlCode.LOCAL_ABORT.value

    @classmethod
    def allow(cls) -> "DummyDecision":
        return cls(True)

    @classmethod
    def deny(cls, code: str = RunnerControlCode.LOCAL_ABORT.value) -> "DummyDecision":
        RunnerControlCode(code)
        return cls(False, code)


@dataclass(frozen=True, slots=True, repr=False)
class BridgeResult:
    classification: str
    state: str
    error_code: str | None
    post_cas_uncertain: bool
    counters: BridgeCounters
    commitments: Mapping[str, str]
    transcript: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            f"BridgeResult(classification={self.classification!r}, state={self.state!r}, "
            f"error_code={self.error_code!r}, post_cas_uncertain={self.post_cas_uncertain!r})"
        )

    def public_projection(self) -> dict[str, Any]:
        safe = {
            "schema": "bridge-public-evidence.v1",
            "classification": self.classification,
            "state": self.state,
            "error_code": self.error_code,
            "post_cas_uncertain": self.post_cas_uncertain,
            "transcript": list(self.transcript),
            "counts": self.counters.public(),
            "commitments": dict(self.commitments),
        }
        encoded = _canonical_json(safe, limit=MAX_CONTROL_PAYLOAD_BYTES)
        forbidden = (
            "container_identity",
            "volume_identity",
            "target_id",
            "volume_id",
            "image_id",
            "artifact_filename",
            "execution_row_id",
            "execution_id",
            "spool_hmac_key",
        )
        if any(token.encode("utf-8") in encoded for token in forbidden):
            raise BridgeError("PROTOCOL_FAILURE")
        return safe


def _snapshot_mapping(snapshot: Any, name: str) -> Mapping[str, Any]:
    value = _read_field(snapshot, name)
    if not isinstance(value, Mapping):
        raise BridgeError("STORE_STATE_INVALID")
    return value


def _load_initial_snapshot(store: Any, epoch_ref: str) -> Any:
    try:
        snapshot = store.load_epoch(epoch_ref)
        record = _snapshot_mapping(snapshot, "record")
        binding = _snapshot_mapping(snapshot, "artifact_binding")
        ledger = _snapshot_mapping(snapshot, "ledger")
        spool = _snapshot_mapping(snapshot, "spool")
        if (
            record.get("state") != "INITIALISED"
            or record.get("artifact_binding_state") != "PENDING"
            or binding.get("artifact_binding_state") != "PENDING"
            or ledger.get("state") != "UNCONSUMED"
            or spool.get("state") != "OPEN"
            or spool.get("last_stage") != "NONE"
        ):
            raise BridgeError("STORE_STATE_INVALID")
        return snapshot
    except BridgeError:
        raise
    except Exception as error:
        raise BridgeError("STORE_STATE_INVALID") from error


def _make_plan(store: Any, snapshot: Any, barrier_utc: str, recovery_host_platform: str) -> RecoveryPlanV1:
    record = _snapshot_mapping(snapshot, "record")
    private = _snapshot_mapping(snapshot, "private_identities")
    return RecoveryPlanV1(
        epoch_ref=_validate_ref(record["epoch_ref"], "epoch_ref"),
        authority_ref=_validate_ref(record["authority_ref"], "authority_ref"),
        barrier_utc=barrier_utc,
        container_identity=_validate_private_text(private["container_identity"], "container_identity"),
        volume_identity=_validate_private_text(private["volume_identity"], "volume_identity"),
        runner_identity=_validate_private_text(private["runner_identity"], "runner_identity"),
        salt=_validate_private_text(private["salt"], "salt"),
        recovery_host_platform=recovery_host_platform,
    )


def _safe_abandon(store: Any, epoch_ref: str, counters: BridgeCounters) -> bool:
    try:
        snapshot = store.load_epoch(epoch_ref)
        record = _snapshot_mapping(snapshot, "record")
        ledger = _snapshot_mapping(snapshot, "ledger")
        spool = _snapshot_mapping(snapshot, "spool")
        if record.get("state") in {"ABANDONED", "CONSUMED", "SUPERSEDED"}:
            return False
        if ledger.get("state") == "CONSUMED" and spool.get("last_stage") != "RESTORE_BEGIN":
            return False
        store.abandon(epoch_ref)
        counters.abandon_calls += 1
        return True
    except Exception:
        return False


class ControllerBridge:
    def __init__(
        self,
        store: Any,
        epoch_ref: str,
        barrier_utc: str,
        *,
        image_source: SyntheticImageSource | None = None,
        artifact_source: SyntheticArtifactProvider | None = None,
        recovery_host_platform: str = "linux",
        local_platform: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        randomness: Callable[[int], bytes] = os.urandom,
        decision: DummyDecision | None = None,
    ):
        if not callable(clock) or not callable(randomness):
            raise TypeError("clock and randomness must be callable")
        self.store = store
        self.epoch_ref = epoch_ref
        self.barrier_utc = validate_barrier_utc(barrier_utc)
        self.image_source = image_source or SyntheticImageSource()
        self.artifact_source = artifact_source or SyntheticArtifactProvider()
        self.recovery_host_platform = recovery_host_platform
        self.local_platform = local_platform or os.name
        if self.local_platform not in {"nt", "posix"}:
            raise BridgeError("PLATFORM_UNSUPPORTED")
        self.clock = clock
        self.randomness = randomness
        self.decision = decision or DummyDecision.allow()
        self.counters = BridgeCounters()
        self.transcript: list[str] = []
        self.commitments: dict[str, str] = {
            "locator_source": CANONICAL_LOCATOR_SOURCE_COMMITMENT,
            "locator_package": CANONICAL_LOCATOR_PACKAGE_BINDING,
        }
        self._stage = "PRE_CAS"
        self._post_cas_uncertain = False
        self._restore_begin_durable = False
        self._agent: FixedRemoteAgent | None = None
        self._graph: BridgeKeyGraph | None = None
        self._session = SessionBudget()
        self._session_sequence = 0

    def _reload(self) -> Any:
        self.counters.reload_calls += 1
        return self.store.load_epoch(self.epoch_ref)

    def _send_authenticated(
        self,
        key: bytes,
        direction: int,
        message: int,
        payload: Mapping[str, Any],
    ) -> AuthenticatedFrame:
        self._session_sequence += 1
        payload_bytes = _canonical_json(dict(payload), limit=MAX_CONTROL_PAYLOAD_BYTES)
        frame_nonce = hashlib.sha256(
            _lp("frame-nonce.v1", str(self._session_sequence), str(message), key)
        ).digest()[:16]
        frame = encode_authenticated_frame(
            key,
            direction,
            message,
            self._session_sequence,
            self._graph.n_session if self._graph is not None else b"",
            payload_bytes,
            frame_nonce=frame_nonce,
        )
        decoded = decode_authenticated_frame(key, frame)
        self._session.add(decoded)
        self.counters.session_frames = self._session.frames
        self.counters.session_bytes = self._session.bytes
        return decoded

    def _assert_bound_reload(self, snapshot: Any, row_id: int, filename: str, artifact_commitment: str) -> None:
        record = _snapshot_mapping(snapshot, "record")
        binding = _snapshot_mapping(snapshot, "artifact_binding")
        ledger = _snapshot_mapping(snapshot, "ledger")
        spool = _snapshot_mapping(snapshot, "spool")
        if not (
            record.get("state") == "INITIALISED"
            and record.get("artifact_binding_state") == "BOUND"
            and binding.get("artifact_binding_state") == "BOUND"
            and binding.get("execution_row_id") == str(row_id)
            and binding.get("artifact_filename") == filename
            and binding.get("artifact_commitment") == artifact_commitment
            and record.get("artifact_commitment") == artifact_commitment
            and ledger.get("state") == "UNCONSUMED"
            and spool.get("last_stage") == "NONE"
        ):
            raise BridgeError("STORE_STATE_INVALID")

    def _ingest_stage(self, stage: str, payload: Mapping[str, Any]) -> None:
        frame = self.store.prepare_runner_frame(self.epoch_ref, stage, dict(payload))
        self.store.ingest_frame(self.epoch_ref, frame)
        if stage == "EPOCH_READY":
            self.counters.epoch_ready_frames += 1
        elif stage == "RUNNER_STARTED":
            self.counters.runner_started_frames += 1
        elif stage == "RESTORE_BEGIN":
            self.counters.restore_begin_frames += 1
        self.transcript.append(stage)

    def _classify_cas(
        self,
        started: Any,
        transition_id: str,
        transition_commitment: str,
        cas_result: Any,
        cas_error: BaseException | None,
    ) -> tuple[str, Any]:
        observed = self._reload()
        self.counters.cas_classification_reload_calls += 1
        ledger = _snapshot_mapping(observed, "ledger")
        record = _snapshot_mapping(observed, "record")
        spool = _snapshot_mapping(observed, "spool")
        if (
            ledger.get("state") == "CONSUMED"
            and ledger.get("transition_id") == transition_id
            and ledger.get("transition_target") == "RESTORE_STARTED"
            and ledger.get("transition_data_commitment") == transition_commitment
            and record.get("state") == "ACTIVE"
            and spool.get("last_stage") == "RUNNER_STARTED"
        ):
            return "A", observed
        started_ledger = _snapshot_mapping(started, "ledger")
        started_record = _snapshot_mapping(started, "record")
        started_spool = _snapshot_mapping(started, "spool")
        if (
            cas_error is not None
            and getattr(cas_error, "safety_state", None) == "UNCONSUMED"
            and ledger == started_ledger
            and record == started_record
            and spool == started_spool
        ):
            return "B", observed
        return "C", observed

    def _result(self, classification: str, error_code: str | None) -> BridgeResult:
        try:
            snapshot = self.store.load_epoch(self.epoch_ref)
            state = _snapshot_mapping(snapshot, "record").get("state", "UNKNOWN")
        except Exception:
            state = "UNKNOWN"
        return BridgeResult(
            classification=classification,
            state=state,
            error_code=error_code,
            post_cas_uncertain=self._post_cas_uncertain,
            counters=self.counters,
            commitments=dict(self.commitments),
            transcript=tuple(self.transcript),
        )

    def run(self) -> BridgeResult:
        snapshot: Any | None = None
        try:
            snapshot = _load_initial_snapshot(self.store, self.epoch_ref)
            plan = _make_plan(
                self.store,
                snapshot,
                self.barrier_utc,
                self.recovery_host_platform,
            )
            record = _snapshot_mapping(snapshot, "record")
            private = _snapshot_mapping(snapshot, "private_identities")
            record_commitment = self.store.record_digest(self.epoch_ref)
            runner_commitment = record["runner_commitment"]
            self._graph = derive_local_key_graph(
                spool_hmac_key=private["spool_hmac_key"],
                salt=private["salt"],
                epoch_ref=plan.epoch_ref,
                authority_ref=plan.authority_ref,
                runner_identity=plan.runner_identity,
                n_remote=self.randomness(32),
                n_local=self.randomness(32),
                barrier_utc=self.barrier_utc,
                record_commitment=record_commitment,
                runner_commitment=runner_commitment,
            )
            self._agent = FixedRemoteAgent(
                plan,
                image_source=self.image_source,
                artifact_source=self.artifact_source,
                counters=self.counters,
            )
            boot = self._agent.boot(runner_commitment)
            self._send_authenticated(
                self._graph.k_boot,
                DIRECTION_LOCAL_TO_REMOTE,
                MESSAGE_BOOT,
                boot,
            )
            self.transcript.append("BOOT")
            validate_boot_payload(boot)
            ready = self._agent.ready()
            self._send_authenticated(
                self._graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                MESSAGE_READY,
                ready,
            )
            self.transcript.append("READY")
            decode_control(encode_control(ready), "READY")
            discovery = self._agent.discover()
            self.counters.locator_calls += 1
            self.counters.discovery_messages += 1
            self.transcript.append("DISCOVERY")
            self.commitments["isolation"] = discovery.isolation_commitment
            discovery_wire = discovery.wire_payload()
            self._send_authenticated(
                self._graph.k_session,
                DIRECTION_REMOTE_TO_LOCAL,
                MESSAGE_DISCOVERY,
                discovery_wire,
            )
            decode_control(encode_control(discovery_wire), "DISCOVERY")
            self.counters.bind_calls += 1
            actual_artifact = self.store.bind_artifact_v2(
                self.epoch_ref,
                discovery.execution_row_id,
                discovery.artifact_filename,
            )
            if not _is_commitment(actual_artifact):
                raise BridgeError("STORE_TRANSITION_FAILED")
            bound = self._reload()
            self._assert_bound_reload(
                bound,
                discovery.execution_row_id,
                discovery.artifact_filename,
                actual_artifact,
            )
            self.store.mark_ready(self.epoch_ref)
            self._ingest_stage("EPOCH_READY", {"state": "READY", "isolation_commitment": discovery.isolation_commitment})
            self.store.activate(self.epoch_ref)
            self._ingest_stage("RUNNER_STARTED", {"state": "RUNNER_STARTED", "image_commitment": discovery.image_admission.image_commitment})
            started = self._reload()
            pre_cas_ledger_digest = self.store.ledger_digest(self.epoch_ref)
            transition, transition_id, transition_commitment = build_restore_transition(
                epoch_ref=plan.epoch_ref,
                authority_ref=plan.authority_ref,
                runner_commitment=runner_commitment,
                runner_bundle_commitment=CANONICAL_LOCATOR_PACKAGE_BINDING,
                barrier_utc=self.barrier_utc,
                artifact_commitment=actual_artifact,
                isolation_commitment=discovery.isolation_commitment,
                pre_cas_ledger_digest=pre_cas_ledger_digest,
            )
            self.counters.cas_attempts += 1
            self.transcript.append("CAS")
            cas_result = None
            cas_error: BaseException | None = None
            try:
                cas_result = self.store.consume_restore(
                    self.epoch_ref,
                    transition_id,
                    expected_digest=pre_cas_ledger_digest,
                    data=transition,
                )
            except BaseException as error:
                cas_error = error
            cas_classification, _observed = self._classify_cas(
                started,
                transition_id,
                transition_commitment,
                cas_result,
                cas_error,
            )
            self.transcript[-1] = "CAS_" + cas_classification
            counter_name = "cas_" + cas_classification.lower()
            setattr(self.counters, counter_name, getattr(self.counters, counter_name) + 1)
            self._stage = "POST_CAS" if cas_classification in {"A", "C"} else "PRE_CAS"
            if cas_classification == "B":
                _safe_abandon(self.store, self.epoch_ref, self.counters)
                return self._result("FAILURE", "STORE_TRANSITION_FAILED")
            if cas_classification == "C":
                self._post_cas_uncertain = True
                return self._result("FAILURE", "POST_CAS_UNCERTAIN")
            self._ingest_stage("RESTORE_BEGIN", {"ref": transition_id, "commitment": transition_commitment})
            self._restore_begin_durable = True
            consumed_record_digest = self.store.record_digest(self.epoch_ref)
            self.commitments["artifact"] = actual_artifact
            self.commitments["transition"] = transition_commitment
            self.commitments["record"] = consumed_record_digest
            graph = self._graph.with_isolation(discovery.isolation_commitment)
            self._graph = graph
            capability = proceed_commitment(
                graph,
                actual_artifact,
                discovery.isolation_commitment,
                transition_id,
                pre_cas_ledger_digest,
                transition_commitment,
                consumed_record_digest,
            )
            token = _grant_token(graph, capability)
            proceed_payload = {
                "type": "PROCEED",
                "version": 1,
                "epoch_digest": graph.epoch_commitment,
                "authority_digest": graph.authority_commitment,
                "runner_digest": graph.runner_commitment,
                "bundle_digest": graph.bundle_commitment,
                "barrier_utc": self.barrier_utc,
                "artifact_commitment": actual_artifact,
                "isolation_commitment": discovery.isolation_commitment,
                "transition_id": transition_id,
                "pre_cas_ledger_digest": pre_cas_ledger_digest,
                "transition_data_commitment": transition_commitment,
                "consumed_record_digest": consumed_record_digest,
                "grant": base64.urlsafe_b64encode(token).decode("ascii").rstrip("="),
            }
            decode_control(encode_control(proceed_payload), "PROCEED")
            if not self.decision.permitted:
                self._post_cas_uncertain = True
                self._send_authenticated(
                    graph.k_proceed,
                    DIRECTION_LOCAL_TO_REMOTE,
                    MESSAGE_ABORT,
                    {"type": "ABORT", "version": 1, "code": self.decision.code},
                )
                self.transcript.append("ABORT")
                self._agent.cleanup()
                _safe_abandon(self.store, self.epoch_ref, self.counters)
                return self._result("FAILURE", self.decision.code)
            self.counters.proceed_messages += 1
            self.transcript.append("PROCEED")
            self._send_authenticated(
                graph.k_proceed,
                DIRECTION_LOCAL_TO_REMOTE,
                MESSAGE_PROCEED,
                proceed_payload,
            )
            remote = self._agent.accept_proceed(
                graph,
                proceed_payload,
                artifact_commitment=actual_artifact,
                transition_id=transition_id,
                decision=self.decision,
            )
            self.counters.result_messages += 1
            self.transcript.append("RESULT")
            self._send_authenticated(
                graph.k_proceed,
                DIRECTION_REMOTE_TO_LOCAL,
                MESSAGE_RESULT,
                {
                    "type": "RESULT",
                    "version": 1,
                    "classification": remote.classification,
                    "result_commitment": remote.result_commitment,
                },
            )
            finality_error = ProcessSupervisor.finality_error(
                remote.terminal_evidence,
                expected_exit=EXIT_SUCCESS if remote.classification == "SUCCESS" else EXIT_RUNNER_ABORT,
            )
            if finality_error is not None:
                self._post_cas_uncertain = True
                _safe_abandon(self.store, self.epoch_ref, self.counters)
                return self._result("FAILURE", finality_error)
            if remote.classification != "SUCCESS":
                _safe_abandon(self.store, self.epoch_ref, self.counters)
                return self._result("FAILURE", remote.error_code)
            self._ingest_stage(
                "COMMIT",
                {"classification": "SUCCESS", "commitment": remote.result_commitment},
            )
            self.counters.commits += 1
            self.commitments["result"] = remote.result_commitment
            return self._result("SUCCESS", None)
        except BridgeError as error:
            if self._stage == "POST_CAS" and error.code == "POST_CAS_UNCERTAIN":
                self._post_cas_uncertain = True
            elif self._stage == "PRE_CAS":
                _safe_abandon(self.store, self.epoch_ref, self.counters)
            return self._result("FAILURE", error.code if error.code in PUBLIC_ERROR_CODES else "PROTOCOL_FAILURE")
        except Exception:
            if self._stage == "PRE_CAS":
                _safe_abandon(self.store, self.epoch_ref, self.counters)
            return self._result("FAILURE", "PROTOCOL_FAILURE")
        finally:
            if self._agent is not None:
                try:
                    self._agent.cleanup()
                except Exception:
                    if self._stage == "POST_CAS":
                        self._post_cas_uncertain = True


def run_controller_bridge(
    store: Any,
    epoch_ref: str,
    barrier_utc: str,
    *,
    image_source: SyntheticImageSource | None = None,
    artifact_source: SyntheticArtifactProvider | None = None,
    recovery_host_platform: str = "linux",
    local_platform: str | None = None,
    clock: Callable[[], float] = time.monotonic,
    randomness: Callable[[int], bytes] = os.urandom,
) -> BridgeResult:
    return ControllerBridge(
        store,
        epoch_ref,
        barrier_utc,
        image_source=image_source,
        artifact_source=artifact_source,
        recovery_host_platform=recovery_host_platform,
        local_platform=local_platform,
        clock=clock,
        randomness=randomness,
    ).run()


def run_dummy_controller_bridge(
    store: Any,
    epoch_ref: str,
    barrier_utc: str,
    *,
    decision: DummyDecision | None = None,
    image_source: SyntheticImageSource | None = None,
    artifact_source: SyntheticArtifactProvider | None = None,
    recovery_host_platform: str = "linux",
    local_platform: str | None = None,
    clock: Callable[[], float] = time.monotonic,
    randomness: Callable[[int], bytes] = os.urandom,
) -> BridgeResult:
    return ControllerBridge(
        store,
        epoch_ref,
        barrier_utc,
        image_source=image_source,
        artifact_source=artifact_source,
        recovery_host_platform=recovery_host_platform,
        local_platform=local_platform,
        clock=clock,
        randomness=randomness,
        decision=decision or DummyDecision.allow(),
    ).run()


def main() -> int:
    # The operational bridge has no CLI launcher. This keeps accidental direct
    # execution fail-closed and prevents any live/provider action.
    return 66


if __name__ == "__main__":
    raise SystemExit(main())
