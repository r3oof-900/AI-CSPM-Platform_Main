"""
AI-CSPM Professional Reporting & In-Place Auto-Remediation Engine
Generates interactive Executive HTML Dashboards, Standalone Visual DAG Graphs, and applies In-Place Least-Privilege Terraform Patches.
"""

import os
import re
import json
import html
import shutil
from typing import Dict, Any, Optional, List


def _read_text_preserve_eol(path: str) -> tuple:
    """Reads text normalized to LF while remembering original EOL style ('\\r\\n' or '\\n')."""
    with open(path, "r", encoding="utf-8", newline="") as f:
        raw = f.read()
    eol = "\r\n" if "\r\n" in raw else "\n"
    return raw.replace("\r\n", "\n"), eol


def _write_text_preserve_eol(path: str, text: str, eol: str) -> None:
    """Writes text preserving original LF/CRLF line endings."""
    out = text.replace("\r\n", "\n")
    if eol == "\r\n":
        out = out.replace("\n", "\r\n")
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(out)


def _sev_text(val: Any, default: str = "MEDIUM") -> str:
    """Normalizes Severity enum/string representations (including Python 3.14 'Severity.CRITICAL')."""
    if val is None:
        return default
    if hasattr(val, "value"):
        return str(val.value).upper()
    s = str(val).strip()
    if "." in s:
        s = s.split(".")[-1]
    return s.upper() or default


def _find_hcl_block_span(
    content: str,
    target_name: Optional[str],
    block_keyword: str = "resource",
    resource_type: str = "aws_iam_policy"
) -> Optional[tuple]:
    """Finds the (start, end) character span of a matching HCL resource or data block."""
    blocks = []
    pattern = rf'{re.escape(block_keyword)}\s+"{re.escape(resource_type)}"\s+"([^"]+)"\s*\{{'
    for m in re.finditer(pattern, content):
        start = m.start()
        brace_open = m.end() - 1
        depth = 0
        idx = brace_open
        end = len(content)
        while idx < len(content):
            ch = content[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
            idx += 1
        blocks.append((m.group(1), start, end, content[start:end]))

    if not blocks:
        return None
    if target_name:
        for res_label, start, end, body in blocks:
            if (
                res_label == target_name
                or re.search(rf'(?:name|bucket)\s*=\s*(?:aws_s3_bucket\.)?"?{re.escape(target_name)}', body)
                or (resource_type == "aws_s3_bucket_policy" and f".{target_name}." in body)
            ):
                return (start, end)
    # Fallback to first block containing kms:Decrypt / kms:* with wildcard Resource, or public Principal
    for _, start, end, body in blocks:
        if resource_type == "aws_s3_bucket_policy" and re.search(
            r'(?:Principal\s*=|"Principal"\s*:)\s*(?:["\']\*["\']|\{[\s\S]*?["\']\*["\'][\s\S]*?\})',
            body,
        ):
            return (start, end)
        if ("kms:Decrypt" in body or "kms:*" in body) and re.search(
            r'(?:Resource\s*=|"Resource"\s*:)\s*(?:["\']\*["\']|\[\s*["\']\*["\']\s*\])',
            body,
        ):
            return (start, end)
    return (blocks[0][1], blocks[0][2])


def _merge_hcl_condition_into_block(block_text: str, cond_key: str, cond_val_expr: str) -> str:
    """Safely merges a StringEquals entry into an existing Condition HCL block without duplicating keys."""
    if cond_key in block_text:
        return block_text
    str_eq_match = re.search(r'(StringEquals\s*=\s*\{)', block_text)
    if str_eq_match:
        pos = str_eq_match.end()
        return block_text[:pos] + f'\n            "{cond_key}" = {cond_val_expr}' + block_text[pos:]
    cond_match = re.search(r'(Condition\s*=\s*\{)', block_text)
    if cond_match:
        pos = cond_match.end()
        return (
            block_text[:pos]
            + f'\n          StringEquals = {{\n            "{cond_key}" = {cond_val_expr}\n          }}'
            + block_text[pos:]
        )
    return block_text


def _merge_json_text_condition(block_text: str, cond_key: str, cond_val_str: str) -> str:
    """Safely merges a StringEquals entry into an existing JSON-formatted \"Condition\" block."""
    if f'"{cond_key}"' in block_text:
        return block_text
    str_eq_m = re.search(r'("StringEquals"\s*:\s*\{)', block_text)
    if str_eq_m:
        pos = str_eq_m.end()
        tail_non_ws = block_text[pos:].lstrip()
        comma = "" if tail_non_ws.startswith("}") else ","
        return block_text[:pos] + f'\n            "{cond_key}": "{cond_val_str}"{comma}' + block_text[pos:]
    cond_m = re.search(r'("Condition"\s*:\s*\{)', block_text)
    if cond_m:
        pos = cond_m.end()
        tail_non_ws = block_text[pos:].lstrip()
        comma = "" if tail_non_ws.startswith("}") else ","
        return (
            block_text[:pos]
            + f'\n          "StringEquals": {{\n            "{cond_key}": "{cond_val_str}"\n          }}{comma}'
            + block_text[pos:]
        )
    return block_text


def _enclosing_stmt_span(block_text: str, pos: int) -> tuple:
    """Finds the enclosing Statement object { ... } boundaries containing `pos` inside an IAM/resource policy block."""
    stmt_kw = re.search(r'(?:"Statement"|Statement)\s*(?::|=)\s*\[', block_text)
    if not stmt_kw or pos < stmt_kw.end():
        return (0, len(block_text))
    arr_start = stmt_kw.end() - 1
    bracket_depth = 0
    brace_stack: List[int] = []
    idx = arr_start
    while idx < len(block_text):
        ch = block_text[idx]
        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth -= 1
            if bracket_depth <= 0:
                break
        elif ch == "{":
            brace_stack.append(idx)
        elif ch == "}":
            if brace_stack:
                s_open = brace_stack.pop()
                if not brace_stack and bracket_depth == 1 and s_open <= pos <= idx:
                    return (s_open, idx + 1)
        idx += 1
    return (0, len(block_text))


def _is_deny_stmt(stmt_text: str) -> bool:
    """Returns True if an isolated IAM/resource statement block explicitly declares Effect = Deny."""
    return bool(re.search(r'(?:Effect\s*=|"Effect"\s*:)\s*["\']Deny["\']', stmt_text, re.IGNORECASE))


def _inject_condition_after_resource(block_text: str, cond_key: str, hcl_val_expr: str, json_val_str: str, search_from: int = 0) -> str:
    """Inserts or merges Condition inside either HCL or JSON-heredoc statement text starting at search_from."""
    slice_txt = block_text[search_from:]
    is_json_style = bool(re.search(r'"Resource"\s*:', slice_txt))
    res_pat = (
        r'("Resource"\s*:\s*(?:\[[\s\S]*?\]|"[^"\n]*"))'
        if is_json_style
        else r'(Resource\s*=\s*(?:\[[\s\S]*?\]|[^\n]+))'
    )
    if re.search(r'"Condition"\s*:\s*\{', slice_txt):
        return block_text[:search_from] + _merge_json_text_condition(slice_txt, cond_key, json_val_str)
    if re.search(r'\bCondition\s*=\s*\{', slice_txt):
        return block_text[:search_from] + _merge_hcl_condition_into_block(slice_txt, cond_key, hcl_val_expr)
    if is_json_style:
        res_m = re.search(res_pat, slice_txt)
        if res_m:
            r_end = res_m.end()
            after = slice_txt[r_end:]
            trailing = "," if after.lstrip().startswith(",") else ""
            if trailing:
                comma_idx = r_end + len(after) - len(after.lstrip())
                slice_txt = slice_txt[:r_end] + slice_txt[comma_idx + 1:]
            cond_snippet = (
                f',\n        "Condition": {{\n          "StringEquals": {{\n'
                f'            "{cond_key}": "{json_val_str}"\n          }}\n        }}{trailing}'
            )
            slice_txt = slice_txt[:r_end] + cond_snippet + slice_txt[r_end:]
        return block_text[:search_from] + slice_txt
    cond_hcl = (
        f'\\1\n        Condition = {{\n          StringEquals = {{\n'
        f'            "{cond_key}" = {hcl_val_expr}\n          }}\n        }}'
    )
    return block_text[:search_from] + re.sub(res_pat, cond_hcl, slice_txt, count=1)


def _merge_json_condition(stmt: Dict[str, Any], cond_key: str, cond_val: str):
    """Merges a StringEquals entry into an IAM JSON statement's Condition dict without duplicating keys."""
    cond = stmt.setdefault("Condition", {})
    if not isinstance(cond, dict):
        cond = {}
        stmt["Condition"] = cond
    str_eq = cond.setdefault("StringEquals", {})
    if not isinstance(str_eq, dict):
        str_eq = {}
        cond["StringEquals"] = str_eq
    str_eq[cond_key] = cond_val


def _patch_standalone_json_policy(
    target_file: str,
    key_arn: str,
    bucket_arn: str,
    cond_key: str = "kms:EncryptionContext:aws:s3:arn"
) -> str:
    raw_text, eol = _read_text_preserve_eol(target_file)
    data = json.loads(raw_text)
    stmts = data.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
        data["Statement"] = stmts
    for stmt in stmts:
        if not isinstance(stmt, dict) or str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if any("kms:Decrypt" in a or "kms:*" in a or a == "*" for a in actions):
            if stmt.get("Resource") in ("*", ["*"]):
                stmt["Resource"] = key_arn
            _merge_json_condition(stmt, cond_key, bucket_arn)
    _write_text_preserve_eol(target_file, json.dumps(data, indent=2), eol)
    return target_file


def _patch_data_policy_document(
    target_dir: str,
    doc_name: str,
    resource_expr: str,
    cond_key: str,
    cond_val_expr: str,
    backup_tracker: set
) -> Optional[str]:
    """Patches `data "aws_iam_policy_document" "<doc_name>"` in-place when referenced by aws_iam_policy."""
    for root, _, files in os.walk(target_dir):
        for fname in files:
            if not fname.endswith(".tf") or fname.endswith(".backup") or fname.startswith("remediated_"):
                continue
            fp = os.path.join(root, fname)
            try:
                content, fp_eol = _read_text_preserve_eol(fp)
            except Exception:
                continue
            span = _find_hcl_block_span(content, doc_name, block_keyword="data", resource_type="aws_iam_policy_document")
            if not span:
                continue
            if fp not in backup_tracker:
                bkp = fp + ".backup"
                if not os.path.exists(bkp):
                    shutil.copy2(fp, bkp)
                backup_tracker.add(fp)
            b_start, b_end = span
            block_text = content[b_start:b_end]
            # Locate the statement { ... } block using balanced braces, skipping Deny and preferring kms:Decrypt/kms:*
            wildcard_candidates: List[tuple] = []
            kms_wildcard_candidates: List[tuple] = []
            for sm in re.finditer(r'\bstatement\s*\{', block_text):
                s_open = sm.end() - 1
                depth = 0
                idx = s_open
                s_end = len(block_text)
                while idx < len(block_text):
                    if block_text[idx] == "{":
                        depth += 1
                    elif block_text[idx] == "}":
                        depth -= 1
                        if depth == 0:
                            s_end = idx + 1
                            break
                    idx += 1
                s_body = block_text[s_open:s_end]
                if _is_deny_stmt(s_body):
                    continue
                if re.search(r'resources\s*=\s*\[[^\]]*["\']\*["\'][^\]]*\]', s_body):
                    wildcard_candidates.append((s_open, s_end))
                    if re.search(r'kms:Decrypt|kms:\*|"\*"', s_body):
                        kms_wildcard_candidates.append((s_open, s_end))

            target_stmt_span = (
                kms_wildcard_candidates[0]
                if kms_wildcard_candidates
                else (wildcard_candidates[0] if wildcard_candidates else None)
            )
            if target_stmt_span:
                s_open, s_end = target_stmt_span
                stmt_body = block_text[s_open:s_end]
                stmt_body = re.sub(
                    r'resources\s*=\s*\[[^\]]*["\']\*["\'][^\]]*\]',
                    f"resources = [{resource_expr}]",
                    stmt_body,
                    count=1,
                )
                if cond_key not in stmt_body:
                    cond_block = (
                        f'\n    condition {{\n'
                        f'      test     = "StringEquals"\n'
                        f'      variable = "{cond_key}"\n'
                        f'      values   = [{cond_val_expr}]\n'
                        f'    }}\n  '
                    )
                    stmt_body = stmt_body[:-1] + cond_block + "}"
                block_text = block_text[:s_open] + stmt_body + block_text[s_end:]
            patched = content[:b_start] + block_text + content[b_end:]
            _write_text_preserve_eol(fp, patched, fp_eol)
            return fp
    return None


def apply_auto_remediation(
    target_dir: str,
    remediation: Any,
    attack_path: Optional[Any] = None
) -> Optional[str]:
    """
    Applies true in-place auto-remediation across:
      - aws_iam_policy (HCL jsonencode, JSON heredoc, and data.aws_iam_policy_document)
      - Standalone .json IAM policy files
      - Direct aws_kms_key resource policies and aws_s3_bucket_policy resources
    Merges into existing Condition blocks cleanly without duplicating Condition keys.
    """
    if not remediation:
        return None

    # 1. Extract metadata from attack path & AI remediation snippet
    key_name = "payment_key"
    key_arn = None
    bucket_name = "payment_vault"
    bucket_arn = None
    role_name = None
    role_arn = None
    source_file = None
    policy_name = None
    has_iam_policy = False
    has_kms_key = False
    has_s3_bucket = False

    if attack_path:
        nodes = attack_path.nodes if hasattr(attack_path, "nodes") else attack_path.get("nodes", [])
        for n in nodes:
            ntype = n.get("type")
            name = n.get("name", "")
            if ntype in ["KMS_KEY", "NodeType.KMS_KEY"]:
                has_kms_key = True
                key_name = name or key_name
                key_arn = n.get("key_arn") or key_arn
                if not source_file:
                    source_file = n.get("source_file")
            elif ntype in ["S3_BUCKET", "NodeType.S3_BUCKET"]:
                has_s3_bucket = True
                bucket_name = name or bucket_name
                bucket_arn = n.get("bucket_arn") or bucket_arn
                if not source_file:
                    source_file = n.get("source_file")
            elif ntype in ["IAM_ROLE", "NodeType.IAM_ROLE"]:
                role_name = name
                role_arn = n.get("role_arn")
            elif ntype in ["IAM_POLICY", "NodeType.IAM_POLICY"]:
                has_iam_policy = True
                policy_name = name
                source_file = n.get("source_file")

    # Prefer explicit CMK / S3 ARNs synthesized by AI engine if available
    remed_code_str = remediation.remediated_code if hasattr(remediation, "remediated_code") else remediation.get("remediated_code", "")
    ai_kms_arn_m = re.search(r'"(arn:aws:kms:[^"]+)"', remed_code_str or "")
    if ai_kms_arn_m and not key_arn:
        key_arn = ai_kms_arn_m.group(1)
    ai_s3_arn_m = re.search(r'"(arn:aws:s3:::[^"/]+)"', remed_code_str or "")
    if ai_s3_arn_m and not bucket_arn:
        bucket_arn = ai_s3_arn_m.group(1)

    # Scan target_dir for local TF resource identifiers and attribute names
    def _collect_tf_blocks(content_str: str, res_type: str) -> List[tuple]:
        found: List[tuple] = []
        for rm in re.finditer(rf'resource\s+"{re.escape(res_type)}"\s+"([^"]+)"\s*\{{', content_str):
            s = rm.end() - 1
            d, pos = 0, s
            while pos < len(content_str):
                if content_str[pos] == "{":
                    d += 1
                elif content_str[pos] == "}":
                    d -= 1
                    if d == 0:
                        pos += 1
                        break
                pos += 1
            found.append((rm.group(1), content_str[s:pos]))
        return found

    def _resolve_tf_label(
        entries: List[tuple],
        hint_name: Optional[str],
        hint_arn: Optional[str] = None,
        fallback_first: bool = True,
    ) -> Optional[str]:
        if not entries:
            return None
        candidates = []
        if hint_name:
            candidates.extend([hint_name, hint_name.replace("-", "_")])
        if hint_arn and "/" in str(hint_arn):
            tail = str(hint_arn).split("/")[-1]
            candidates.extend([tail, tail.replace("-", "_")])
        for lbl, body in entries:
            if lbl in candidates:
                return lbl
            decl_m = re.search(r'\b(?:name|bucket)\s*=\s*"([^"]+)"', body)
            if decl_m and decl_m.group(1) in candidates:
                return lbl
        return entries[0][0] if fallback_first else None

    tf_kms_entries: List[tuple] = []
    tf_s3_entries: List[tuple] = []
    tf_role_entries: List[tuple] = []
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.endswith(".tf") and not f.endswith(".backup") and not f.startswith("remediated_"):
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8") as tf_in:
                        c = tf_in.read()
                        tf_kms_entries.extend(_collect_tf_blocks(c, "aws_kms_key"))
                        tf_s3_entries.extend(_collect_tf_blocks(c, "aws_s3_bucket"))
                        tf_role_entries.extend(_collect_tf_blocks(c, "aws_iam_role"))
                except Exception:
                    pass

    tf_kms_names = [lbl for lbl, _ in tf_kms_entries]
    tf_s3_names = [lbl for lbl, _ in tf_s3_entries]
    resolved_kms = _resolve_tf_label(tf_kms_entries, key_name, key_arn)
    if resolved_kms and key_name not in tf_kms_names:
        key_name = resolved_kms
    resolved_s3 = _resolve_tf_label(tf_s3_entries, bucket_name, bucket_arn)
    if resolved_s3 and bucket_name not in tf_s3_names:
        bucket_name = resolved_s3

    # Standalone JSON IAM policy file (skip exported AWS snapshot bundles without top-level Statement)
    if source_file and os.path.exists(source_file) and source_file.endswith(".json"):
        try:
            with open(source_file, "r", encoding="utf-8") as jf:
                jdata = json.load(jf)
        except Exception:
            jdata = None
        if isinstance(jdata, dict) and "Statement" in jdata:
            backup_path = source_file + ".backup"
            if not os.path.exists(backup_path):
                shutil.copy2(source_file, backup_path)
            return _patch_standalone_json_policy(
                source_file,
                key_arn=key_arn or f"arn:aws:kms:us-east-1:123456789012:key/{key_name}",
                bucket_arn=bucket_arn or f"arn:aws:s3:::{bucket_name}",
            )

    # 2. Determine target .tf file and resource type
    target_res_type = "aws_iam_policy" if has_iam_policy else ("aws_kms_key" if has_kms_key else "aws_s3_bucket_policy")
    target_res_name = policy_name if has_iam_policy else (key_name if has_kms_key else bucket_name)

    target_file = None
    if source_file and os.path.exists(source_file) and source_file.endswith(".tf"):
        if target_res_type == "aws_s3_bucket_policy":
            with open(source_file, "r", encoding="utf-8") as f_chk:
                if "aws_s3_bucket_policy" in f_chk.read():
                    target_file = source_file
        else:
            target_file = source_file

    if not target_file:
        for root, _, files in os.walk(target_dir):
            for f in files:
                if f.endswith(".tf") and not f.endswith(".backup") and not f.startswith("remediated_"):
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, "r", encoding="utf-8") as tf_in:
                            content = tf_in.read()
                            if target_res_type in content:
                                target_file = fp
                                break
                    except Exception:
                        pass
            if target_file:
                break

    if not target_file or not os.path.exists(target_file):
        return None

    # 3. Create backup without overwriting pristine backup
    backup_path = target_file + ".backup"
    if not os.path.exists(backup_path):
        shutil.copy2(target_file, backup_path)

    tf_content, tf_eol = _read_text_preserve_eol(target_file)

    key_ref_expr = f"aws_kms_key.{key_name}.arn" if key_name in tf_kms_names else (f'"{key_arn}"' if key_arn else f"aws_kms_key.{key_name}.arn")
    bucket_ref_expr = f"aws_s3_bucket.{bucket_name}.arn" if bucket_name in tf_s3_names else (f'"{bucket_arn}"' if bucket_arn else f"aws_s3_bucket.{bucket_name}.arn")

    # 4a. Patch aws_s3_bucket_policy
    if target_res_type == "aws_s3_bucket_policy":
        span = _find_hcl_block_span(tf_content, target_res_name, resource_type="aws_s3_bucket_policy")
        if span:
            b_start, b_end = span
            block_text = tf_content[b_start:b_end]
            tf_role_ref = _resolve_tf_label(
                tf_role_entries,
                role_name,
                role_arn,
                fallback_first=not (role_name or role_arn),
            )
            principal_expr = f"aws_iam_role.{tf_role_ref}.arn" if tf_role_ref else (f'"{role_arn}"' if role_arn else f'"{role_name}"')
            principal_interp = f"${{{principal_expr}}}" if not principal_expr.startswith('"') else principal_expr.strip('"')
            # Scope patching strictly to the Allow statement containing the wildcard Principal
            s_start, s_end = (0, len(block_text))
            for pm in re.finditer(
                r'(?:Principal\s*=|"Principal"\s*:)\s*(?:["\']\*["\']|\{[\s\S]*?["\']\*["\'][\s\S]*?\})',
                block_text,
            ):
                cs, ce = _enclosing_stmt_span(block_text, pm.start())
                if not _is_deny_stmt(block_text[cs:ce]):
                    s_start, s_end = cs, ce
                    break
            stmt_slice = block_text[s_start:s_end]
            is_json_princ = bool(re.search(r'"Principal"\s*:', stmt_slice))
            scalar_pat = r'"Principal"\s*:\s*"\*"' if is_json_princ else r'Principal\s*=\s*["\']\*["\']'
            map_pat = (
                r'("Principal"\s*:\s*\{[\s\S]*?\})'
                if is_json_princ
                else r'(Principal\s*=\s*\{[\s\S]*?\})'
            )
            if re.search(scalar_pat, stmt_slice):
                repl = (
                    f'"Principal": {{"AWS": "{principal_interp}"}}'
                    if is_json_princ
                    else f"Principal = {{\n          AWS = {principal_expr}\n        }}"
                )
                patched_stmt = re.sub(scalar_pat, repl, stmt_slice, count=1)
            else:
                def _scrub_wildcard_in_principal(m: re.Match) -> str:
                    seg = m.group(1)
                    target_val = f'"{principal_interp}"' if is_json_princ else principal_expr
                    return re.sub(r'["\']\*["\']', target_val, seg)
                patched_stmt = re.sub(map_pat, _scrub_wildcard_in_principal, stmt_slice, count=1)
            patched_stmt = _inject_condition_after_resource(
                patched_stmt,
                cond_key="aws:PrincipalArn",
                hcl_val_expr=principal_expr,
                json_val_str=principal_interp,
            )
            patched_block = block_text[:s_start] + patched_stmt + block_text[s_end:]
            _write_text_preserve_eol(target_file, tf_content[:b_start] + patched_block + tf_content[b_end:], tf_eol)
        return target_file

    # 4b. Patch aws_kms_key resource policy
    if target_res_type == "aws_kms_key":
        span = _find_hcl_block_span(tf_content, target_res_name, resource_type="aws_kms_key")
        if span:
            b_start, b_end = span
            block_text = tf_content[b_start:b_end]
            cond_key = "kms:EncryptionContext:aws:s3:arn" if has_s3_bucket else "kms:ViaService"
            cond_val = bucket_ref_expr if has_s3_bucket else '"s3.amazonaws.com"'
            bkt_interp = f"${{{bucket_ref_expr}}}" if not bucket_ref_expr.startswith('"') else bucket_ref_expr.strip('"')
            cond_json_val = bkt_interp if has_s3_bucket else "s3.amazonaws.com"
            s_start, s_end = (-1, -1)
            for km in re.finditer(r'kms:Decrypt|kms:\*', block_text):
                cs, ce = _enclosing_stmt_span(block_text, km.start())
                if not _is_deny_stmt(block_text[cs:ce]) and cond_key not in block_text[cs:ce]:
                    s_start, s_end = cs, ce
                    if "kms:Decrypt" in block_text[cs:ce]:
                        break
            if s_start != -1:
                patched_stmt = _inject_condition_after_resource(
                    block_text[s_start:s_end],
                    cond_key=cond_key,
                    hcl_val_expr=cond_val,
                    json_val_str=cond_json_val,
                )
                patched_block = block_text[:s_start] + patched_stmt + block_text[s_end:]
                _write_text_preserve_eol(target_file, tf_content[:b_start] + patched_block + tf_content[b_end:], tf_eol)
        return target_file

    # 4c. Patch aws_iam_policy (data doc / HCL jsonencode / JSON heredoc)
    span = _find_hcl_block_span(tf_content, policy_name, resource_type="aws_iam_policy")
    b_start, b_end = span if span else (0, len(tf_content))
    block_text = tf_content[b_start:b_end]

    # Check if policy references data.aws_iam_policy_document.<doc>.json
    data_ref_m = re.search(r'data\.aws_iam_policy_document\.([a-zA-Z0-9_-]+)\.json', block_text)
    if data_ref_m:
        patched_doc = _patch_data_policy_document(
            target_dir,
            doc_name=data_ref_m.group(1),
            resource_expr=key_ref_expr,
            cond_key="kms:EncryptionContext:aws:s3:arn",
            cond_val_expr=bucket_ref_expr,
            backup_tracker={target_file},
        )
        if patched_doc:
            return patched_doc

    hcl_res_pat = re.compile(r'(#\s*[^\n]*\n\s*)?Resource\s*=\s*(?:["\']\*["\']|\[\s*["\']\*["\']\s*\])', re.MULTILINE)
    json_res_pat = re.compile(r'"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])')

    # Scope patching strictly to the enclosing Statement containing KMS decrypt wildcard grant
    s_start, s_end = (0, len(block_text))
    found_stmt = False
    for km in re.finditer(r'kms:Decrypt|kms:\*', block_text):
        cand_s, cand_e = _enclosing_stmt_span(block_text, km.start())
        cand_txt = block_text[cand_s:cand_e]
        if not _is_deny_stmt(cand_txt) and (hcl_res_pat.search(cand_txt) or json_res_pat.search(cand_txt)):
            s_start, s_end = cand_s, cand_e
            found_stmt = True
            break
    if not found_stmt:
        any_res = hcl_res_pat.search(block_text) or json_res_pat.search(block_text)
        if any_res:
            s_start, s_end = _enclosing_stmt_span(block_text, any_res.start())
    stmt_slice = block_text[s_start:s_end]

    if hcl_res_pat.search(stmt_slice):
        has_existing_condition = bool(re.search(r'\bCondition\s*=\s*\{', stmt_slice))
        if has_existing_condition:
            patched_stmt = hcl_res_pat.sub(
                f"# REMEDIATED BY AI-CSPM: Scoped down from wildcard '*'\n        Resource = {key_ref_expr}",
                stmt_slice,
                count=1,
            )
            patched_stmt = _merge_hcl_condition_into_block(
                patched_stmt,
                "kms:EncryptionContext:aws:s3:arn",
                bucket_ref_expr,
            )
        else:
            replacement_block = f"""# REMEDIATED BY AI-CSPM: Scoped down from wildcard '*' to explicit Customer Managed Key
        Resource = {key_ref_expr}

        # REMEDIATED BY AI-CSPM: Cryptographically bound to target S3 storage vault
        Condition = {{
          StringEquals = {{
            "kms:EncryptionContext:aws:s3:arn" = {bucket_ref_expr}
          }}
        }}"""
            patched_stmt = hcl_res_pat.sub(replacement_block, stmt_slice, count=1)
        patched_block = block_text[:s_start] + patched_stmt + block_text[s_end:]
    elif json_res_pat.search(stmt_slice):
        key_interp = f"${{{key_ref_expr}}}" if not key_ref_expr.startswith('"') else key_ref_expr.strip('"')
        bkt_interp = f"${{{bucket_ref_expr}}}" if not bucket_ref_expr.startswith('"') else bucket_ref_expr.strip('"')
        has_existing_json_cond = bool(re.search(r'"Condition"\s*:\s*\{', stmt_slice))
        if has_existing_json_cond:
            patched_stmt = json_res_pat.sub(f'"Resource": "{key_interp}"', stmt_slice, count=1)
            patched_stmt = _merge_json_text_condition(patched_stmt, "kms:EncryptionContext:aws:s3:arn", bkt_interp)
        else:
            patched_stmt = json_res_pat.sub(f'"Resource": "{key_interp}"', stmt_slice, count=1)
            patched_stmt = _inject_condition_after_resource(
                patched_stmt,
                cond_key="kms:EncryptionContext:aws:s3:arn",
                hcl_val_expr=bucket_ref_expr,
                json_val_str=bkt_interp,
            )
        patched_block = block_text[:s_start] + patched_stmt + block_text[s_end:]
    else:
        return target_file

    patched_content = tf_content[:b_start] + patched_block + tf_content[b_end:] if span else patched_block
    _write_text_preserve_eol(target_file, patched_content, tf_eol)

    # 5. Clean up any redundant duplicate patch files in target directory
    redundant_patch = os.path.join(target_dir, "remediated_least_privilege_patch.tf")
    if os.path.exists(redundant_patch):
        try:
            os.remove(redundant_patch)
        except Exception:
            pass

    return target_file


def generate_html_report(scan_data: Dict[str, Any]) -> str:
    """
    Generates a modern, standalone, offline-ready Executive HTML Dashboard report.
    """
    metrics = scan_data.get("metrics", {})
    attack_paths = scan_data.get("attack_paths", [])
    misconfigs = scan_data.get("misconfigurations", [])
    consensus = scan_data.get("consensus", {})
    remediation = scan_data.get("remediation", {})
    target_dir = scan_data.get("target_source") or scan_data.get("target_directory", "Unknown")

    has_attack_paths = len(attack_paths) > 0
    crit_high_misconfigs = sum(
        1 for m in misconfigs if _sev_text(m.get("severity"), "") in ("CRITICAL", "HIGH")
    )
    has_any_misconfigs = len(misconfigs) > 0

    if has_attack_paths:
        status_color = "#ef4444"
        status_text = "CRITICAL RISKS DETECTED"
        status_badge_bg = "rgba(239, 68, 68, 0.15)"
        status_border = "#ef4444"
    elif crit_high_misconfigs > 0:
        status_color = "#f59e0b"
        status_text = f"CROSS-LAYER CONTAINED ({crit_high_misconfigs} HIGH/CRIT FINDINGS)"
        status_badge_bg = "rgba(245, 158, 11, 0.15)"
        status_border = "#f59e0b"
    elif has_any_misconfigs:
        status_color = "#06b6d4"
        status_text = "CROSS-LAYER CONTAINED (HARDENING ADVISED)"
        status_badge_bg = "rgba(6, 182, 212, 0.15)"
        status_border = "#06b6d4"
    else:
        status_color = "#10b981"
        status_text = "100% CONTAINED & SECURE"
        status_badge_bg = "rgba(16, 185, 129, 0.15)"
        status_border = "#10b981"

    # Build Attack Path Cards HTML
    ap_html = ""
    for ap in attack_paths:
        ap_sev = _sev_text(ap.get("severity"), "CRITICAL")
        ap_badge_cls = "badge-danger" if ap_sev == "CRITICAL" else "badge-warning" if ap_sev == "HIGH" else "badge-info"
        steps_html = "".join([f'<li class="step-item"><span class="step-num">{i+1}</span>{html.escape(s)}</li>' for i, s in enumerate(ap.get("steps", []))])
        ap_html += f"""
        <div class="card attack-card">
            <div class="card-header danger">
                <span class="badge {ap_badge_cls}">{html.escape(ap_sev)} SEVERITY</span>
                <h3>{html.escape(ap.get('title', 'Cross-Layer Attack Path'))}</h3>
                <span class="path-id">{html.escape(ap.get('id', ''))}</span>
            </div>
            <div class="card-body">
                <div class="attack-meta">
                    <p><strong>Root Cause:</strong> {html.escape(ap.get('root_cause', ''))}</p>
                    <p><strong>Impact:</strong> {html.escape(ap.get('impact', ''))}</p>
                </div>
                <h4>Compromise Chain Execution (Hop-by-Hop):</h4>
                <ul class="steps-list">
                    {steps_html}
                </ul>
            </div>
        </div>
        """

    if not ap_html:
        if has_any_misconfigs:
            ap_html = f"""
        <div class="card secure-card">
            <div class="card-body text-center">
                <div class="secure-icon">🛡️</div>
                <h3>Zero Cross-Layer Exploitation Paths Detected</h3>
                <p>Cross-layer KMS wildcard paths are contained. However, {len(misconfigs)} standalone configuration finding(s) ({crit_high_misconfigs} CRITICAL/HIGH) remain in the posture audit table below.</p>
            </div>
        </div>
        """
        else:
            ap_html = """
        <div class="card secure-card">
            <div class="card-body text-center">
                <div class="secure-icon">🛡️</div>
                <h3>Zero Critical Exploitation Paths Detected</h3>
                <p>All Kubernetes Workloads, Cloud IAM policies, KMS keys, and S3 buckets passed all posture checks. Environment is 100% contained and hardened.</p>
            </div>
        </div>
        """

    # Build Multi-Agent Debate Cards HTML
    red_team = consensus.get("red_team", {})
    blue_team = consensus.get("blue_team", {})
    arbiter = consensus.get("arbiter", {})

    # Build Misconfigurations Table Rows
    misconfig_rows = ""
    for m in misconfigs:
        sev = _sev_text(m.get("severity"), "MEDIUM")
        sev_class = "badge-danger" if sev == "CRITICAL" else "badge-warning" if sev == "HIGH" else "badge-info"
        controls = ", ".join(m.get("compliance_controls", [])[:2])
        misconfig_rows += f"""
        <tr>
            <td><code>{html.escape(m.get('id', ''))}</code></td>
            <td><span class="badge {sev_class}">{html.escape(sev)}</span></td>
            <td><span class="layer-pill">{html.escape(m.get('layer', ''))}</span></td>
            <td><strong>{html.escape(m.get('title', ''))}</strong></td>
            <td><code>{html.escape(m.get('resource_id', ''))}</code></td>
            <td class="dim">{html.escape(controls)}</td>
        </tr>
        """

    # Build Remediation Patch Code across ALL remediations (supports multi-path scans)
    remediations_list = scan_data.get("remediations") or ([remediation] if remediation else [])
    remed_sections_html = ""
    for idx_r, r_item in enumerate(remediations_list):
        if not isinstance(r_item, dict):
            continue
        code_txt = r_item.get("remediated_code", "")
        if not code_txt:
            continue
        ap_id = r_item.get("attack_path_id", f"AP-{idx_r + 1:03d}")
        exp_txt = r_item.get("explanation", "")
        remed_sections_html += f"""
        <div class="card">
            <div class="card-header">
                <strong>Patch for {html.escape(ap_id)}</strong>
                <span class="dim">{html.escape(r_item.get('risk_reduction', ''))}</span>
            </div>
            <div class="card-body">
                {f'<p style="margin-bottom:12px; color:#cbd5e1; font-size:13.5px;">{html.escape(exp_txt)}</p>' if exp_txt else ''}
                <pre><code>{html.escape(code_txt)}</code></pre>
            </div>
        </div>
        """

    if not remed_sections_html:
        if has_any_misconfigs:
            fallback_msg = (
                f"# Cross-layer KMS wildcard paths are contained.\n"
                f"# Address {len(misconfigs)} standalone posture finding(s) ({crit_high_misconfigs} CRITICAL/HIGH) in the audit table below."
            )
        else:
            fallback_msg = "# Environment baseline already hardened. No patch required."
        remed_sections_html = f"""
        <div class="card">
            <div class="card-body">
                <pre><code>{html.escape(fallback_msg)}</code></pre>
            </div>
        </div>
        """

    cvss_score = arbiter.get("cvss_v4_score", 0.0 if not has_attack_paths else 9.8)
    try:
        cvss_num = float(cvss_score)
    except Exception:
        cvss_num = 0.0
    cvss_rating = arbiter.get("cvss_rating") or ("NONE (SECURE)" if cvss_num == 0.0 else "CRITICAL" if cvss_num >= 9.0 else "HIGH")
    cvss_color = "#10b981" if cvss_num == 0.0 else "#ef4444" if cvss_num >= 7.0 else "#f59e0b"

    def _pct_to_kpi_class(val_str: Any) -> str:
        try:
            num = int(str(val_str).rstrip("%").strip())
        except Exception:
            num = 0
        if num >= 80:
            return "kpi-success"
        if num >= 40:
            return "kpi-yellow"
        return "kpi-danger"

    containment_cls = _pct_to_kpi_class(metrics.get("containment_score", "0%"))
    posture_cls = _pct_to_kpi_class(metrics.get("posture_score", "100%" if not misconfigs else "0%"))
    sev_counts = metrics.get("severity_counts") or {}
    sev_summary_html = " ".join(
        f'<span class="badge {"badge-danger" if s == "CRITICAL" else "badge-warning" if s == "HIGH" else "badge-info"}">{s}: {int(sev_counts.get(s, 0))}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        if int(sev_counts.get(s, 0)) > 0
    ) or '<span class="badge badge-info">0 Findings</span>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-CSPM Executive Security Audit Report</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-border: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg);
            color: var(--text-primary);
            font-family: var(--font);
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        /* Header */
        .report-header {{
            background: linear-gradient(135deg, #111827 0%, #1e1b4b 100%);
            border: 1px solid var(--surface-border);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        .header-title h1 {{
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 12px;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header-title p {{ color: var(--text-secondary); margin-top: 6px; font-size: 14px; }}
        .header-status {{
            background: {status_badge_bg};
            border: 1px solid {status_border};
            color: {status_color};
            padding: 12px 24px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 15px;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        /* KPI Cards */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
            margin-bottom: 30px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 22px;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s;
        }}
        .kpi-card:hover {{ transform: translateY(-3px); }}
        .kpi-val {{ font-size: 32px; font-weight: 800; margin-top: 8px; }}
        .kpi-label {{ color: var(--text-secondary); font-size: 13px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }}
        .kpi-danger .kpi-val {{ color: var(--accent-red); }}
        .kpi-success .kpi-val {{ color: var(--accent-green); }}
        .kpi-cyan .kpi-val {{ color: var(--accent-cyan); }}
        .kpi-yellow .kpi-val {{ color: var(--accent-yellow); }}

        /* Sections */
        .section-title {{
            font-size: 20px;
            font-weight: 700;
            margin: 32px 0 16px 0;
            display: flex;
            align-items: center;
            gap: 10px;
            color: #e2e8f0;
        }}

        /* Cards */
        .card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }}
        .card-header {{
            padding: 18px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--surface-border);
        }}
        .card-header.danger {{ background: rgba(239, 68, 68, 0.08); border-color: rgba(239, 68, 68, 0.3); }}
        .card-body {{ padding: 24px; }}
        
        /* Attack Chain Steps */
        .steps-list {{ list-style: none; margin-top: 14px; display: flex; flex-direction: column; gap: 10px; }}
        .step-item {{
            background: rgba(31, 41, 55, 0.5);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 14px;
            font-size: 14px;
        }}
        .step-num {{
            background: var(--accent-red);
            color: white;
            font-weight: 700;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            flex-shrink: 0;
        }}

        /* Agents Grid */
        .agents-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .agent-card {{
            border-radius: 12px;
            padding: 22px;
            background: var(--surface);
            border: 1px solid var(--surface-border);
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .agent-card.red {{ border-top: 4px solid var(--accent-red); }}
        .agent-card.blue {{ border-top: 4px solid var(--accent-cyan); }}
        .agent-card.arbiter {{ border-top: 4px solid var(--accent-green); }}
        .agent-role {{ font-size: 12px; text-transform: uppercase; font-weight: 700; color: var(--text-secondary); }}
        .agent-title {{ font-size: 17px; font-weight: 700; }}
        .agent-desc {{ font-size: 14px; color: #cbd5e1; flex-grow: 1; }}

        /* Code Block */
        pre {{
            background: #0b0f19;
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 18px;
            overflow-x: auto;
            color: #38bdf8;
            font-family: "Fira Code", monospace;
            font-size: 13px;
            line-height: 1.5;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13.5px;
        }}
        th, td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--surface-border);
        }}
        th {{
            background: rgba(17, 24, 39, 0.8);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }}
        tr:hover td {{ background: rgba(31, 41, 55, 0.4); }}
        code {{
            background: rgba(15, 23, 42, 0.8);
            padding: 3px 6px;
            border-radius: 4px;
            color: #7dd3fc;
            font-family: monospace;
            font-size: 12px;
        }}

        /* Badges */
        .badge {{
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            display: inline-block;
        }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-info {{ background: rgba(6, 182, 212, 0.2); color: #67e8f9; border: 1px solid rgba(6, 182, 212, 0.4); }}
        .layer-pill {{
            background: rgba(147, 51, 234, 0.15);
            color: #c084fc;
            border: 1px solid rgba(147, 51, 234, 0.3);
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }}
        .dim {{ color: #64748b; font-size: 12px; }}

        .secure-card {{
            padding: 40px;
            border: 1px solid rgba(16, 185, 129, 0.3);
            background: rgba(16, 185, 129, 0.05);
        }}
        .secure-icon {{ font-size: 48px; margin-bottom: 12px; }}
        .footer {{
            text-align: center;
            color: #64748b;
            font-size: 13px;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--surface-border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="report-header">
            <div class="header-title">
                <h1>🛡️ AI-CSPM Executive Security Audit</h1>
                <p>Multi-Tier Cloud Identity & Cryptographic DAG Assessment | Target: <code>{html.escape(target_dir)}</code></p>
            </div>
            <div class="header-status">
                <span>{status_text}</span>
            </div>
        </header>

        <!-- KPI Summary Cards -->
        <div class="kpi-grid">
            <div class="kpi-card kpi-cyan">
                <div class="kpi-label">Discovered Assets</div>
                <div class="kpi-val">{metrics.get('total_assets', 0)}</div>
            </div>
            <div class="kpi-card kpi-yellow">
                <div class="kpi-label">DAG Relationships</div>
                <div class="kpi-val">{metrics.get('total_relationships', 0)}</div>
            </div>
            <div class="kpi-card kpi-danger">
                <div class="kpi-label">Lethal Attack Paths</div>
                <div class="kpi-val">{metrics.get('critical_attack_paths', 0)}</div>
            </div>
            <div class="kpi-card {containment_cls}">
                <div class="kpi-label">Blast Radius Containment</div>
                <div class="kpi-val">{metrics.get('containment_score', '0%')}</div>
            </div>
            <div class="kpi-card {posture_cls}">
                <div class="kpi-label">Security Posture Score</div>
                <div class="kpi-val">{metrics.get('posture_score', 'N/A')}</div>
                <div style="margin-top:8px; display:flex; gap:6px; flex-wrap:wrap;">{sev_summary_html}</div>
            </div>
        </div>

        <!-- Cross-Layer Attack Path -->
        <h2 class="section-title">⚡ Cross-Layer Attack Paths & Compromise Chains</h2>
        {ap_html}

        <!-- Multi-Agent Consensus Deliberation -->
        <h2 class="section-title">🤖 Multi-Agent Security Debate & Consensus Decision</h2>
        <div class="agents-grid">
            <div class="agent-card red">
                <span class="agent-role">🔴 Offense / Exploit Simulation</span>
                <h4 class="agent-title">{html.escape(red_team.get('agent_name', 'Agent 1: Red-Team'))}</h4>
                <p class="agent-desc">{html.escape(red_team.get('attack_vector_en', ''))}</p>
                <div class="agent-stat"><strong>Blast Radius:</strong> {html.escape(str(red_team.get('blast_radius', '')))}</div>
            </div>
            <div class="agent-card blue">
                <span class="agent-role">🔵 Defense / IaC Hardening</span>
                <h4 class="agent-title">{html.escape(blue_team.get('agent_name', 'Agent 2: Blue-Team'))}</h4>
                <p class="agent-desc">{html.escape(blue_team.get('defense_strategy_en', ''))}</p>
                <div class="agent-stat"><strong>Status:</strong> {html.escape(str(blue_team.get('status', '')))}</div>
            </div>
            <div class="agent-card arbiter">
                <span class="agent-role">⚖️ Risk & Compliance Arbiter</span>
                <h4 class="agent-title">{html.escape(arbiter.get('agent_name', 'Agent 3: Arbiter'))}</h4>
                <p class="agent-desc">{html.escape(arbiter.get('consensus_verdict_en', ''))}</p>
                <div class="agent-stat"><strong>CVSS 4.0 Score:</strong> <span style="color:{cvss_color}; font-weight:800;">{html.escape(str(cvss_score))} {html.escape(str(cvss_rating))}</span></div>
            </div>
        </div>

        <!-- Synthesized Least-Privilege Terraform Remediation -->
        <h2 class="section-title">🛠️ Synthesized Scoped Terraform (Least-Privilege Patch)</h2>
        {remed_sections_html}

        <!-- Misconfigurations Audit Table -->
        <h2 class="section-title">📋 Comprehensive Posture & Misconfigurations Audit ({len(misconfigs)} Findings)</h2>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Severity</th>
                        <th>Layer</th>
                        <th>Security Defect</th>
                        <th>Target Resource</th>
                        <th>Compliance Controls</th>
                    </tr>
                </thead>
                <tbody>
                    {misconfig_rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Generated by <strong>AI-CSPM Standalone CLI v1.0.0</strong> | Multi-Tier Contextual Security Synthesizer</p>
        </div>
    </div>
</body>
</html>
"""
    return html_content


def generate_interactive_graph_html(graph_data: Dict[str, Any]) -> str:
    """
    Generates an interactive, standalone SVG-based visual graph with curved Bezier paths,
    edge type labels, and full-info hover tooltips that opens offline in any browser.
    """
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    layer_order = ["Kubernetes", "IAM", "Cryptography", "Storage"]
    nodes_by_layer: Dict[str, List[Dict[str, Any]]] = {l: [] for l in layer_order}
    for n in nodes:
        layer = n.get("layer", "Kubernetes")
        if layer not in nodes_by_layer:
            nodes_by_layer[layer] = []
            layer_order.append(layer)
        nodes_by_layer[layer].append(n)

    positions: Dict[str, tuple] = {}
    node_col: Dict[str, int] = {}
    x_spacing = 340
    y_spacing = 120
    start_x = 130
    start_y = 70
    box_w = 180
    box_h = 54

    for col_idx, layer in enumerate(layer_order):
        layer_nodes = nodes_by_layer.get(layer, [])
        for row_idx, node in enumerate(layer_nodes):
            x = start_x + (col_idx * x_spacing)
            y = start_y + (row_idx * y_spacing)
            positions[node["id"]] = (x, y)
            node_col[node["id"]] = col_idx

    max_rows = max((len(nodes_by_layer.get(l, [])) for l in layer_order), default=1)
    svg_width = max(1340, start_x + len(layer_order) * x_spacing)
    svg_height = max(460, (start_y - 10) + max_rows * y_spacing)

    svg_edges = ""
    placed_labels: List[tuple] = []
    for e_idx, e in enumerate(edges):
        src = e.get("source")
        tgt = e.get("target")
        if src not in positions or tgt not in positions:
            continue
        x1, y1 = positions[src]
        x2, y2 = positions[tgt]
        c1 = node_col.get(src, 0)
        c2 = node_col.get(tgt, 0)
        is_lethal = bool(e.get("lethal_flaw"))
        edge_type = str(e.get("type", ""))
        color = "#ef4444" if is_lethal else "#38bdf8"
        width = "3.2" if is_lethal else "1.8"
        dash = 'stroke-dasharray="6,4"' if is_lethal else ""

        if c1 == c2:
            # Intra-column vertical connection curved along the LEFT edge so it never overlaps inter-column labels
            sx, sy = x1, y1 + box_h / 2
            tx, ty = x2, y2 + box_h / 2
            ctrl_x = max(24, sx - 52 - (e_idx % 2) * 14)
            path_d = f"M {sx},{sy} C {ctrl_x},{sy} {ctrl_x},{ty} {tx},{ty}"
            lx, ly = ctrl_x + 12, (sy + ty) / 2
        elif c2 - c1 > 1:
            # Cross-column jump: route smoothly along an arc above intermediate boxes
            sx, sy = x1 + box_w / 2, y1
            tx, ty = x2 + box_w / 2, y2
            arc_y = max(18, min(sy, ty) - 38 - (e_idx % 2) * 12)
            path_d = f"M {sx},{sy} C {sx},{arc_y} {tx},{arc_y} {tx},{ty}"
            lx, ly = (sx + tx) / 2, (sy + ty) * 0.125 + arc_y * 0.75
        else:
            # Standard left-to-right cubic Bezier curve
            sx, sy = x1 + box_w, y1 + box_h / 2
            tx, ty = x2, y2 + box_h / 2
            dx = max(48, (tx - sx) * 0.5)
            path_d = f"M {sx},{sy} C {sx + dx},{sy} {tx - dx},{ty} {tx},{ty}"
            lx, ly = (sx + tx) / 2, (sy + ty) / 2 - 8

        svg_edges += (
            f'<g class="graph-edge">'
            f'<title>{html.escape(edge_type)}: {html.escape(src)} -> {html.escape(tgt)}</title>'
            f'<path d="{path_d}" fill="none" stroke="{color}" stroke-width="{width}" {dash} marker-end="url(#arrow)"/>'
        )
        if edge_type:
            short_edge = edge_type.replace("_", " ")
            pill_w = min(148, max(64, len(short_edge) * 6 + 10))
            lx = max(pill_w / 2 + 8, lx)
            base_ly = ly
            for step in (0, -20, 20, -40, 40, -60, 60):
                cand_ly = min(svg_height - 14, max(16, base_ly + step))
                overlaps = any(
                    abs(lx - px) < (pill_w + pw) * 0.5 + 8 and abs(cand_ly - py) < 18
                    for px, py, pw in placed_labels
                )
                if not overlaps:
                    ly = cand_ly
                    break
            placed_labels.append((lx, ly, pill_w))
            svg_edges += (
                f'<rect x="{lx - pill_w / 2:.1f}" y="{ly - 9:.1f}" width="{pill_w}" height="15" rx="4" fill="#090d16" fill-opacity="0.92" stroke="{color}" stroke-opacity="0.45" stroke-width="0.8"/>'
                f'<text x="{lx:.1f}" y="{ly + 2:.1f}" text-anchor="middle" fill="#cbd5e1" font-size="8.5" font-weight="600">{html.escape(short_edge)}</text>'
            )
        svg_edges += "</g>\n"

    svg_nodes = ""
    for n in nodes:
        nid = n.get("id")
        if nid not in positions:
            continue
        x, y = positions[nid]
        ntype = n.get("type", "UNKNOWN")
        label = n.get("label", nid)
        layer = n.get("layer", "Unknown")
        src_file = n.get("source_file", "")

        box_color = "#1e293b"
        border_color = "#38bdf8"
        if layer == "Kubernetes":
            border_color = "#3b82f6"
        elif layer == "IAM":
            border_color = "#a855f7"
        elif layer == "Cryptography":
            border_color = "#f59e0b"
        elif layer == "Storage":
            border_color = "#10b981"

        display_lbl = label if len(label) <= 22 else label[:20] + ".."
        tooltip = f"{label}\nType: {ntype} ({layer})\nID: {nid}" + (f"\nSource: {src_file}" if src_file else "")

        svg_nodes += f"""
            <g class="graph-node" transform="translate({x}, {y})">
                <title>{html.escape(tooltip)}</title>
                <rect width="{box_w}" height="{box_h}" rx="8" fill="{box_color}" stroke="{border_color}" stroke-width="2"/>
                <text x="10" y="20" fill="#94a3b8" font-size="10" font-weight="700">{html.escape(ntype)}</text>
                <text x="10" y="39" fill="#f8fafc" font-size="12" font-weight="600">{html.escape(display_lbl)}</text>
            </g>
            """

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AI-CSPM Interactive Attack Path Graph</title>
    <style>
        body {{ background: #090d16; color: #f8fafc; font-family: sans-serif; margin: 0; padding: 20px; text-align: center; }}
        h2 {{ margin-bottom: 5px; color: #38bdf8; }}
        p {{ color: #94a3b8; font-size: 14px; margin-bottom: 20px; }}
        .svg-container {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; display: inline-block; padding: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); max-width: 100%; overflow-x: auto; }}
        .graph-node:hover rect {{ fill: #334155; cursor: pointer; }}
        .legend {{ margin-top: 20px; display: flex; justify-content: center; gap: 20px; font-size: 13px; }}
        .legend span {{ display: flex; align-items: center; gap: 6px; }}
        .dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
    </style>
</head>
<body>
    <h2>🛡️ Multi-Tier Contextual Security Graph (DAG)</h2>
    <p>End-to-End attack path visualization from Kubernetes In-Cluster Workloads to Cloud Storage Vaults (hover nodes for full details)</p>
    <div class="svg-container">
        <svg width="{svg_width}" height="{svg_height}">
            <defs>
                <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1 L 8 5 L 0 9 z" fill="#64748b"/>
                </marker>
            </defs>
            {svg_edges}
            {svg_nodes}
        </svg>
    </div>
    <div class="legend">
        <span><span class="dot" style="background:#3b82f6;"></span> Kubernetes Workload</span>
        <span><span class="dot" style="background:#a855f7;"></span> IAM Role / Policy</span>
        <span><span class="dot" style="background:#f59e0b;"></span> KMS Key</span>
        <span><span class="dot" style="background:#10b981;"></span> S3 Vault</span>
        <span><span class="dot" style="background:#ef4444;"></span> Lethal Wildcard Flaw</span>
    </div>
</body>
</html>
"""
