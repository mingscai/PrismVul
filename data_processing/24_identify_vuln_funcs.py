#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

def load_json_cache(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        with path.open('r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_json_cache(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write('\n')
    tmp.replace(path)

def cve_record_key(record: dict[str, Any], line_no: int) -> str:
    for key in ('cve_id', 'cve', 'id'):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return f'line:{line_no}'

def collect_chain_candidates(record: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for chain_idx, chain in enumerate(record.get('src_commits_chained') or []):
        if not isinstance(chain, dict):
            continue
        for diff_idx, diff in enumerate(chain.get('diffs') or []):
            if not isinstance(diff, dict):
                continue
            filename = diff.get('filename') or ''
            diff_funcs = diff.get('diff_funcs') or {}
            if not isinstance(diff_funcs, dict):
                continue
            for category in ('modified', 'removed'):
                for func_idx, func in enumerate(diff_funcs.get(category) or []):
                    if not isinstance(func, dict):
                        continue
                    candidates.append({'chain_idx': chain_idx, 'diff_idx': diff_idx, 'category': category, 'func_idx': func_idx, 'filename': filename, 'sig': func.get('sig') or func.get('name') or '', 'code': func.get('code') or func.get('body') or None, 'code_after': func.get('code_after') if category == 'modified' else None, '_func_ref': func, '_chain_ref': chain, '_record_ref': record})
    return candidates

def _get_chain_issues(record, chain):
    all_issues = [iss for iss in record.get('issues') or [] if isinstance(iss, dict)]
    chain_cids = [cid[:12] for cid in chain.get('commit_ids') or [] if cid]
    if not chain_cids:
        return all_issues
    issue_links: set[str] = set()
    for lnk in record.get('src_commit_links') or []:
        h = (lnk.get('hash') or '').lower()
        if not h:
            continue
        for cid in chain_cids:
            if h.startswith(cid.lower()):
                src = lnk.get('source') or ''
                if src.startswith('http'):
                    issue_links.add(src)
                break
    if not issue_links:
        return all_issues
    matched = [iss for iss in all_issues if iss.get('link') in issue_links]
    return matched if matched else all_issues

def _collect_chain_siblings(chain, cand):
    siblings = []
    di_target = cand['diff_idx']
    cat_target = cand['category']
    fi_target = cand['func_idx']
    for diff_idx, diff in enumerate(chain.get('diffs') or []):
        if not isinstance(diff, dict):
            continue
        fname = diff.get('filename') or ''
        df = diff.get('diff_funcs') or {}
        for category in ('modified', 'removed', 'added'):
            for func_idx, func in enumerate(df.get(category) or []):
                if not isinstance(func, dict):
                    continue
                if diff_idx == di_target and category == cat_target and (func_idx == fi_target):
                    continue
                siblings.append({'sig': func.get('sig') or func.get('name') or '', 'file': fname, 'category': category})
    return siblings

def _commit_message_for(record, cid):
    for c in record.get('src_commits') or []:
        if isinstance(c, dict) and (c.get('id') or '') == cid:
            return str(c.get('message') or '').strip()
    return ''

def _chain_func_touches(record, chain):
    chain_ids = list(chain.get('commit_ids') or [])
    chain_set = set(chain_ids)
    if not chain_set:
        return {}
    by_id = {}
    for c in record.get('src_commits') or []:
        cid = (c.get('id') or '').strip() if isinstance(c, dict) else ''
        if cid in chain_set:
            by_id[cid] = c
    touches: dict[tuple, list[tuple[str, str]]] = {}
    for cid in chain_ids:
        c = by_id.get(cid)
        if not c:
            continue
        for d in c.get('diffs') or []:
            if not isinstance(d, dict):
                continue
            fname = d.get('filename') or ''
            df = d.get('diff_funcs') or {}
            for cat in ('modified', 'removed', 'added'):
                for fn in df.get(cat) or []:
                    if not isinstance(fn, dict):
                        continue
                    sig = fn.get('sig') or ''
                    if fname and sig:
                        touches.setdefault((fname, sig), []).append((cid, cat))
    return touches
PROMPT_VERSION_S1 = 'v1_chain_2stage_s1_relevance_no_issues_unified_sys'
PROMPT_VERSION_S2 = 'v1_chain_2stage_s2_followup_with_issues_unified_sys'
SYSTEM_PROMPT = 'You are a security analyst reviewing a fix for a known CVE.\n\nThe fix is given as a "commit chain" — one or more git commits that together\nimplement the fix. The chain has:\n  - root_parent: the pre-fix git state (the "before" reference)\n  - leaf:        the post-fix git state (the "after" reference)\n  - len:         number of commits in the chain\nThe "before/after" code shown for each function corresponds to its state at\nroot_parent and leaf respectively (i.e. the net effect of the entire chain).\n\nYou are given:\n  1. CVE description\n  2. The chain\'s structure and each chain commit\'s message\n  3. A single candidate function modified or removed in the fix, with its\n     code before and (if available) after the fix\n  4. Other functions modified/removed/added anywhere in the chain\n     (signatures only)\n  5. (Stage 2 only) ISSUE SUMMARIES — issue tracker context that was\n     deliberately withheld during Stage 1\'s binary triage and is provided\n     in Stage 2 to support the finer-grained decision.\n\nCLASSIFICATION TAXONOMY\n-----------------------\nThere are three terminal classes, organized in a 2-level hierarchy:\n\n  related (a.k.a. vuln_related)        ← umbrella for any substantive fix participation\n    │\n    ├── root_cause_vulnerable\n    │     The candidate\'s own pre-fix logic directly implements the\n    │     vulnerability mechanism described in the CVE (e.g. missing\n    │     validation, incorrect bounds/type handling, unsafe object\n    │     lifetime, stale-pointer dereference, use-after-free, etc.),\n    │     AND the fix changes that exact logic in a security-relevant way.\n    │\n    └── supporting_fix\n          The candidate was modified as part of the security fix and the\n          change is security-related, but the candidate\'s own pre-fix logic\n          does NOT independently implement a core part of the vulnerability\n          mechanism. Instead it propagates, forwards, accommodates, wraps,\n          or complements a fix whose core vulnerable behavior is implemented\n          in another function.\n\n  incidental_or_unrelated              ← outside the umbrella\n    The candidate\'s change is mechanical, stylistic, refactoring, logging,\n    assertion, build, test, or other non-substantive maintenance work, or\n    is only weakly related to the fix and does NOT make a meaningful\n    security-relevant change to the vulnerability mechanism. Examples:\n      - rename / formatting / comment-only edits\n      - test scaffolding or assertion-only additions\n      - build-system / .gn / BUILD.bazel changes\n      - logging or debug instrumentation\n      - drive-by cleanups bundled into the fix commit\n\nImportant: ``root_cause_vulnerable`` and ``supporting_fix`` are BOTH\n``related``. The split between them is made in Stage 2.\n\nTWO-STAGE TASK FLOW\n-------------------\nStage 1 — relevance triage (binary):\n  Decide whether the candidate is ``related`` or ``incidental_or_unrelated``.\n  Be inclusive: any plausible substantive contribution to the security fix\n  should be ``related``; the root-vs-supporting split is deferred to Stage 2.\n  Output a JSON object:\n    {"classification": "related"|"incidental_or_unrelated", "reasoning": "<2-3 sentences>"}\n\nStage 2 — root vs supporting refinement (binary, only when Stage 1 said\n``related``):\n  Stage 2 continues Stage 1\'s conversation — CVE description, chain\n  structure, candidate code (before/after), and chain siblings remain in\n  context from Stage 1\'s user turn. The Stage 2 user turn may add new\n  context (specifically: ISSUE SUMMARIES that were withheld in Stage 1).\n  Refine the candidate to ``root_cause_vulnerable`` or ``supporting_fix``.\n  Output a JSON object:\n    {"classification": "root_cause_vulnerable"|"supporting_fix", "reasoning": "<2-4 sentences>"}\n\nImportant distinctions (apply to both stages):\n  - Destruction-order, cleanup-order, or ownership-management changes can\n    still be ``related`` — and possibly ``root_cause_vulnerable`` — when\n    the CVE describes a lifetime, dangling-pointer, or use-after-free bug.\n    Do not automatically classify such changes as incidental.\n  - Multiple functions in the same chain may both be ``root_cause_vulnerable``\n    when each independently implements a core part of the vulnerability\n    mechanism.\n  - A candidate is more likely to be ``root_cause_vulnerable`` when the\n    fix changes the exact unsafe operation or state transition (e.g. the\n    overflowing copy, missing bounds check, stale dereference, incorrect\n    lifetime transition) rather than only adding an external guard around\n    code whose vulnerable behavior remains implemented elsewhere.\n\nOUTPUT FORMAT (BOTH STAGES)\n---------------------------\nReturn valid JSON only. No markdown fences. No extra keys. The two-key\nschema (``classification`` + ``reasoning``) is the same in both stages;\nonly the value enum for ``classification`` differs per stage as described\nabove.\n'
VALID_S1 = {'related', 'incidental_or_unrelated'}
VALID_S2 = {'root_cause_vulnerable', 'supporting_fix'}
VALID_FINAL = {'root_cause_vulnerable', 'supporting_fix', 'incidental_or_unrelated'}
OUTPUT_SCHEMA_S1 = {'type': 'object', 'properties': {'classification': {'type': 'string', 'enum': sorted(VALID_S1)}, 'reasoning': {'type': 'string'}}, 'required': ['classification', 'reasoning'], 'additionalProperties': False}
OUTPUT_SCHEMA_S2 = {'type': 'object', 'properties': {'classification': {'type': 'string', 'enum': sorted(VALID_S2)}, 'reasoning': {'type': 'string'}}, 'required': ['classification', 'reasoning'], 'additionalProperties': False}

def _common_prompt_head(cve_id: str, record: dict[str, Any], cand: dict[str, Any]) -> list[str]:
    chain = cand['_chain_ref']
    parts: list[str] = [f'CVE ID: {cve_id}\n']
    cve_desc = str(record.get('cve_desc') or '').strip()
    if cve_desc:
        parts.append(f'CVE DESCRIPTION:\n{cve_desc}\n')
    chain_id = chain.get('chain_id')
    chain_len = chain.get('len') or len(chain.get('commit_ids') or [])
    root_parent = chain.get('root_parent_id') or ''
    commit_ids = chain.get('commit_ids') or []
    leaf = commit_ids[-1] if commit_ids else ''
    abs_cherry = chain.get('absorbed_cherries') or []
    abs_dup = chain.get('absorbed_duplicates') or []
    parts.append('COMMIT CHAIN')
    parts.append("A chain is one or more git commits that together implement the fix. The candidate's before/after code is computed at the chain boundary (root_parent .. leaf), i.e. the net effect of all chain commits.")
    parts.append(f'  chain_id           = {chain_id}')
    parts.append(f'  len                = {chain_len}    # number of commits in the chain')
    parts.append(f'  root_parent        = {root_parent[:12]}    # pre-fix git state')
    parts.append(f'  leaf               = {leaf[:12]}    # post-fix git state')
    if abs_cherry:
        sample = ', '.join((c[:12] for c in abs_cherry[:3]))
        more = f' ... +{len(abs_cherry) - 3}' if len(abs_cherry) > 3 else ''
        parts.append(f'  absorbed_cherries  = {len(abs_cherry)}    # cherry-picks of chain commits, collapsed: [{sample}{more}]')
    if abs_dup:
        sample = ', '.join((c[:12] for c in abs_dup[:3]))
        more = f' ... +{len(abs_dup) - 3}' if len(abs_dup) > 3 else ''
        parts.append(f'  absorbed_duplicates = {len(abs_dup)}    # message-hash dedup of parallel commits: [{sample}{more}]')
    parts.append('')
    parts.append('Commits in this chain (in order):')
    for cid in commit_ids:
        msg = _commit_message_for(record, cid).strip()
        parts.append(f'\n=== {cid[:12]} ===')
        parts.append(msg if msg else '(no message)')
    parts.append('')
    touches = _chain_func_touches(record, chain)
    category = cand.get('category', 'modified')
    sig = cand.get('sig') or '(unknown)'
    filename = cand.get('filename') or '(unknown file)'
    code = cand.get('code')
    code_after = cand.get('code_after')
    parts.append(f'CANDIDATE FUNCTION (chain-level action: {category}):')
    parts.append(f'  File: {filename}')
    parts.append(f'  Sig:  {sig}')
    cand_touches = touches.get((filename, sig)) or []
    if cand_touches:
        touched_str = ', '.join((f'{cid[:12]} [{cat}]' for cid, cat in cand_touches))
        parts.append(f'  Touched by chain commit(s): {touched_str}')
    parts.append(f'  Code (before fix, at root_parent):\n{code}')
    if code_after is not None:
        parts.append(f'  Code (after fix, at leaf):\n{code_after}')
    parts.append('')
    siblings = _collect_chain_siblings(chain, cand)
    if siblings:
        parts.append('OTHER FUNCTIONS MODIFIED/REMOVED/ADDED IN THE SAME CHAIN:')
        for sb in siblings:
            sb_sig = sb['sig'] or '(unknown)'
            sb_file = sb['file'] or ''
            sb_cat = sb['category']
            sb_touches = touches.get((sb_file, sb_sig)) or []
            touched_str = '; touched by ' + ', '.join((f'{cid[:12]} [{cat}]' for cid, cat in sb_touches)) if sb_touches else ''
            line = f'  [chain-level: {sb_cat}] {sb_sig}'
            if sb_file:
                line += f'  ({sb_file})'
            line += touched_str
            parts.append(line)
        parts.append('')
    return parts

def build_stage1_user_prompt(cve_id, record, cand) -> str:
    parts = _common_prompt_head(cve_id, record, cand)
    sig = cand.get('sig') or '(unknown)'
    parts.append(f'STAGE 1 — Decide if the candidate function "{sig}" is `related` to the security fix or `incidental_or_unrelated`.')
    return '\n'.join(parts)

def _issue_block_for(record: dict[str, Any] | None, chain: dict[str, Any] | None) -> list[str]:
    if not record or not chain:
        return []
    issues = _get_chain_issues(record, chain)
    summaries = [iss.get('summary') for iss in issues if iss.get('summary')]
    if not summaries:
        return []
    out = ['ISSUE SUMMARIES (additional context for Stage 2):']
    for i, s in enumerate(summaries, start=1):
        out.append(f'[Issue {i}] {s}')
    out.append('')
    return out

def build_stage2_user_prompt(cve_id, record, cand) -> str:
    parts = _common_prompt_head(cve_id, record, cand)
    parts.extend(_issue_block_for(record, cand.get('_chain_ref')))
    sig = cand.get('sig') or '(unknown)'
    parts.append(f'Stage 1 already determined this candidate is RELATED to the fix.\nSTAGE 2 — Decide if "{sig}" is `root_cause_vulnerable` or `supporting_fix`.')
    return '\n'.join(parts)

def build_stage2_followup_prompt(cand) -> str:
    sig = cand.get('sig') or '(unknown)'
    record = cand.get('_record_ref')
    chain = cand.get('_chain_ref')
    parts: list[str] = []
    parts.extend(_issue_block_for(record, chain))
    parts.append(f'''STAGE 2 OF 2 — refinement task:\nStage 1 already classified this candidate as `related`. The issue\nsummaries above (if any) are additional context that was withheld\nduring Stage 1's binary triage. Now refine to a 2-class label using\nthose issues plus the same chain context already provided above\n(CVE description, chain commits, candidate code before/after, and\nchain siblings). Same definitions as before:\n\n  root_cause_vulnerable\n    The candidate's own pre-fix logic directly implements the\n    vulnerability mechanism described in the CVE, AND the fix\n    changes that exact logic in a security-relevant way.\n\n  supporting_fix\n    The candidate was modified as part of the security fix and the\n    change is security-related, but the candidate's own pre-fix\n    logic does not independently implement a core part of the\n    vulnerability mechanism. Instead it propagates, forwards,\n    accommodates, wraps, or complements a fix whose core vulnerable\n    behavior is implemented in another function.\n\nDecide if "{sig}" is `root_cause_vulnerable` or `supporting_fix`.\n\nReturn ONLY a JSON object with these two keys: classification, reasoning.\nFormat: {{"classification": "root_cause_vulnerable"|"supporting_fix", "reasoning": "<2-4 sentences>"}}''')
    return '\n'.join(parts)

def cache_key_s1(prompt: str) -> str:
    h = hashlib.sha256()
    h.update(PROMPT_VERSION_S1.encode('utf-8'))
    h.update(b'\n')
    h.update(prompt.encode('utf-8'))
    return h.hexdigest()

def cache_key_s2(prompt: str) -> str:
    h = hashlib.sha256()
    h.update(PROMPT_VERSION_S2.encode('utf-8'))
    h.update(b'\n')
    h.update(prompt.encode('utf-8'))
    return h.hexdigest()

def _parse_binary(content: str, valid_set: set[str]) -> tuple[str, str]:
    import re
    text = content.strip()
    if '</think>' in text:
        text = text.rsplit('</think>', 1)[1].strip()
    text = re.sub('^```[a-zA-Z]*\\s*', '', text)
    text = re.sub('\\s*```$', '', text).strip()

    def _try(s: str):
        try:
            return json.loads(s)
        except Exception:
            return None
    obj = _try(text)
    if obj is None:
        m = re.search('\\{.*\\}', text, re.DOTALL)
        if m:
            obj = _try(m.group(0)) or _try(m.group(0).replace("\\'", "'"))
        if obj is None:
            obj = _try(text.replace("\\'", "'"))
    if obj is None:
        raise ValueError(f'Cannot parse JSON from: {content[:200]!r}')
    if not isinstance(obj, dict):
        raise ValueError(f'Expected JSON object, got: {type(obj)}')
    cls = obj.get('classification')
    if cls not in valid_set:
        raise ValueError(f'classification not in {valid_set}: {cls!r}')
    return (cls, str(obj.get('reasoning') or ''))

def call_stage_llm(*, client, model, valid_set, max_tokens, max_retries, retry_initial_sleep, thinking_mode, json_schema=None, disable_thinking=False, system_prompt=None, user_prompt=None, messages=None):
    if messages is None:
        messages = [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_prompt}]
    is_gpt = 'gpt' in model.lower()
    tokens_key = 'max_completion_tokens' if is_gpt else 'max_tokens'
    last_error = None
    last_usage = {}
    last_content = ''
    for attempt in range(1, max_retries + 1):
        try:
            kwargs = {'model': model, 'messages': messages, tokens_key: max_tokens}
            extra_body: dict[str, Any] = {}
            if thinking_mode:
                kwargs['reasoning_effort'] = 'high'
                extra_body['thinking'] = {'type': 'enabled'}
            if disable_thinking:
                extra_body['chat_template_kwargs'] = {'enable_thinking': False}
            if json_schema is not None:
                kwargs['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'classification', 'schema': json_schema, 'strict': True}}
                kwargs['temperature'] = 0.7
                kwargs['top_p'] = 0.8
                kwargs['presence_penalty'] = 1.5
                extra_body['top_k'] = 20
            if extra_body:
                kwargs['extra_body'] = extra_body
            resp = client.chat.completions.create(**kwargs)
            choice = resp.choices[0].message
            content = (getattr(choice, 'content', '') or '').strip()
            last_content = content
            ru = getattr(resp, 'usage', None)
            last_usage = {'prompt_tokens': getattr(ru, 'prompt_tokens', None), 'completion_tokens': getattr(ru, 'completion_tokens', None), 'total_tokens': getattr(ru, 'total_tokens', None)}
            if not content:
                raise ValueError('empty response')
            cls, reason = _parse_binary(content, valid_set)
            return (True, cls, reason, content, None, last_usage)
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries:
                time.sleep(retry_initial_sleep * 2 ** (attempt - 1))
    return (False, None, None, last_content, last_error, last_usage)
DEFAULT_INPUT = Path('data/chromium_cve_data.commit_chained.jsonl')
DEFAULT_OUTPUT = Path('data/chromium_cve_data.commit_chained.jsonl')
DEFAULT_CACHE_S1 = Path('cache/vuln_funcs_chain_2stage_s1_cache.json')
DEFAULT_CACHE_S2 = Path('cache/vuln_funcs_chain_2stage_s2_cache.json')

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input-jsonl', type=Path, default=DEFAULT_INPUT)
    ap.add_argument('--output-jsonl', type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument('--model', type=str, default='gpt-5.4', help='OpenAI-compatible model name (deepseek-*/gpt-*/qwen-*).')
    ap.add_argument('--base-url', type=str, default=None)
    ap.add_argument('--api-key', type=str, default=None)
    ap.add_argument('--cache-json-s1', type=Path, default=DEFAULT_CACHE_S1)
    ap.add_argument('--cache-json-s2', type=Path, default=DEFAULT_CACHE_S2)
    ap.add_argument('--thinking-mode', action='store_true', help='DeepSeek v4-pro thinking mode (online OpenAI-compat).')
    ap.add_argument('--max-tokens', type=int, default=1024)
    ap.add_argument('--max-retries', type=int, default=3)
    ap.add_argument('--retry-initial-sleep', type=float, default=2.0)
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--save-every', type=int, default=20)
    ap.add_argument('--max-records', type=int, default=0)
    ap.add_argument('--overwrite', action='store_true')
    ap.add_argument('--reclassify', action='store_true', help='Re-classify even funcs that already have a final classification.')
    ap.add_argument('--demo-prompt', action='store_true', help='Print Stage 1 + Stage 2 prompts for the first candidate; exit.')
    ap.add_argument('--structured-output', action='store_true', help='vLLM guided JSON decoding + disable Qwen3.5 thinking. Massively faster (skips ~2-5K thinking tokens per call) at the cost of chain-of-thought reasoning. Pair with vLLM serve at --base-url.')
    return ap.parse_args()

def main() -> None:
    args = parse_args()
    if args.demo_prompt:
        records = []
        with args.input_jsonl.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        for ridx, record in enumerate(records, start=1):
            cands = collect_chain_candidates(record)
            if not cands:
                continue
            cand = cands[0]
            cve_id = cve_record_key(record, ridx)
            print('=' * 80)
            print(f'DEMO PROMPT — CVE: {cve_id}')
            print(f"Candidate sig: {cand.get('sig', '')}")
            print('=' * 80)
            print('\n────── STAGE 1 (relevance triage, no issue summaries) ──────')
            print('\n--- [S1] SYSTEM ---\n')
            print(SYSTEM_PROMPT)
            print('\n--- [S1] USER ---\n')
            s1_user = build_stage1_user_prompt(cve_id, record, cand)
            print(s1_user)
            print('\n--- [S1] (model would respond with JSON like) ---')
            stub_s1_json = '{"classification": "related", "reasoning": "<2-3 sentences from the model>"}'
            print(stub_s1_json)
            print('\n\n────── STAGE 2 (multi-turn conversation continuing from S1) ──────')
            print('\n--- [S2] FULL CONVERSATION SENT TO MODEL ---\n')
            s2_followup = build_stage2_followup_prompt(cand)
            convo = [('system', SYSTEM_PROMPT), ('user', s1_user), ('assistant', stub_s1_json), ('user', s2_followup)]
            for role, content in convo:
                print(f'[{role}]')
                print(content)
                print()
            print('--- [S2] (model responds with JSON like) ---')
            print('{"classification": "root_cause_vulnerable" | "supporting_fix", "reasoning": "<2-4 sentences>"}')
            print()
            print('--- [S2] LEGACY single-turn user prompt (kept for reference, NOT used in current code path) ---\n')
            print(build_stage2_user_prompt(cve_id, record, cand))
            return
        print('[demo-prompt] no candidates found')
        return
    same = args.input_jsonl.resolve() == args.output_jsonl.resolve()
    if same and (not args.overwrite):
        sys.exit(f'Output equals input ({args.output_jsonl}); pass --overwrite for in-place')
    records: list[dict[str, Any]] = []
    with args.input_jsonl.open() as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f'[input] {len(records)} CVE records')
    work = []
    n_funcs = n_already = 0
    for ridx, record in enumerate(records, start=1):
        for cand in collect_chain_candidates(record):
            n_funcs += 1
            fref = cand['_func_ref']
            cls = fref.get('classification')
            if not args.reclassify and cls in VALID_FINAL:
                n_already += 1
                continue
            cve_id = cve_record_key(record, ridx)
            work.append({'line_no': ridx, 'cve_id': cve_id, 'cand': cand})
    print(f'[plan] chain mod/rem funcs total: {n_funcs}')
    print(f'[plan] already classified (skip):  {n_already}')
    print(f'[plan] funcs needing 2-stage call: {len(work)}')
    if args.max_records > 0:
        work = work[:args.max_records]
        print(f'[plan] capped to --max-records {args.max_records} → {len(work)}')
    if not work:
        print('[done] nothing to classify')
        return
    model_lower = args.model.lower()
    if not args.base_url:
        if 'deepseek' in model_lower:
            args.base_url = 'https://api.deepseek.com/v1'
        elif 'qwen' in model_lower:
            args.base_url = 'https://dashscope.aliyuncs.com/compatible-mode/v1'
    api_key = args.api_key or os.environ.get('DEEPSEEK_API_KEY' if 'deepseek' in model_lower else 'DASHSCOPE_API_KEY' if 'qwen' in model_lower else 'OPENAI_API_KEY')
    if not api_key:
        sys.exit('ERROR: no API key found. Set the appropriate env var or pass --api-key.')
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit('ERROR: pip install openai')
    ck: dict[str, Any] = {'api_key': api_key}
    if args.base_url:
        ck['base_url'] = args.base_url
    client = OpenAI(**ck)
    cache_s1 = load_json_cache(args.cache_json_s1)
    cache_s2 = load_json_cache(args.cache_json_s2)
    print(f'[cache S1] {len(cache_s1)} entries in {args.cache_json_s1}')
    print(f'[cache S2] {len(cache_s2)} entries in {args.cache_json_s2}')
    print(f'[run] model={args.model}  thinking={args.thinking_mode}  workers={args.workers}')
    cache_lock = threading.Lock()
    state_lock = threading.Lock()
    flush_lock = threading.Lock()
    n_done = n_s1_calls = n_s2_calls = n_s1_hits = n_s2_hits = n_error = 0
    n_s1_incidental = n_s1_related = 0
    t0 = time.time()
    output_path = args.output_jsonl

    def flush_jsonl():
        tmp = output_path.with_suffix(output_path.suffix + '.tmp')
        with tmp.open('w') as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')
        tmp.replace(output_path)

    def process_one(idx: int, w: dict[str, Any]) -> None:
        nonlocal n_done, n_s1_calls, n_s2_calls, n_s1_hits, n_s2_hits, n_error
        nonlocal n_s1_incidental, n_s1_related
        cve_id = w['cve_id']
        cand = w['cand']
        fref = cand['_func_ref']
        record = records[w['line_no'] - 1]
        s1_user = build_stage1_user_prompt(cve_id, record, cand)
        s1_key = cache_key_s1(s1_user)
        with cache_lock:
            cached1 = cache_s1.get(s1_key)
        if isinstance(cached1, dict) and cached1.get('classification') in VALID_S1:
            s1_cls = cached1['classification']
            s1_reason = cached1.get('reasoning') or ''
            s1_raw = cached1.get('raw_response')
            with state_lock:
                n_s1_hits += 1
        else:
            ok, s1_cls, s1_reason, s1_raw, err, _ = call_stage_llm(client=client, model=args.model, system_prompt=SYSTEM_PROMPT, user_prompt=s1_user, valid_set=VALID_S1, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, thinking_mode=args.thinking_mode, json_schema=OUTPUT_SCHEMA_S1 if args.structured_output else None, disable_thinking=args.structured_output)
            with state_lock:
                n_s1_calls += 1
            if not ok:
                with state_lock:
                    n_error += 1
                print(f"  [{idx}/{len(work)}] S1-ERROR  {cve_id}  {cand.get('sig', '')[:60]}: {err}")
                return
            with cache_lock:
                cache_s1[s1_key] = {'prompt_version': PROMPT_VERSION_S1, 'model': args.model, 'classification': s1_cls, 'reasoning': s1_reason, 'raw_response': s1_raw, 'updated_at': int(time.time())}
        fref['classification_stage1'] = s1_cls
        fref['reasoning_stage1'] = s1_reason
        if s1_cls == 'incidental_or_unrelated':
            with state_lock:
                n_s1_incidental += 1
            fref['classification'] = 'incidental_or_unrelated'
            fref['reasoning'] = s1_reason
            fref['classification_stage2'] = None
            fref['reasoning_stage2'] = None
            with state_lock:
                n_done += 1
            return
        with state_lock:
            n_s1_related += 1
        if not s1_raw:
            s1_raw = json.dumps({'classification': s1_cls, 'reasoning': s1_reason}, ensure_ascii=False)
        s2_followup = build_stage2_followup_prompt(cand)
        s2_key = cache_key_s2(s1_user + '\n\n##S2FOLLOWUP##\n' + s2_followup)
        with cache_lock:
            cached2 = cache_s2.get(s2_key)
        if isinstance(cached2, dict) and cached2.get('classification') in VALID_S2:
            s2_cls = cached2['classification']
            s2_reason = cached2.get('reasoning') or ''
            s2_raw = cached2.get('raw_response')
            with state_lock:
                n_s2_hits += 1
        else:
            s2_messages = [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': s1_user}, {'role': 'assistant', 'content': s1_raw}, {'role': 'user', 'content': s2_followup}]
            ok, s2_cls, s2_reason, s2_raw, err, _ = call_stage_llm(client=client, model=args.model, messages=s2_messages, valid_set=VALID_S2, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, thinking_mode=args.thinking_mode, json_schema=OUTPUT_SCHEMA_S2 if args.structured_output else None, disable_thinking=args.structured_output)
            with state_lock:
                n_s2_calls += 1
            if not ok:
                with state_lock:
                    n_error += 1
                print(f"  [{idx}/{len(work)}] S2-ERROR  {cve_id}  {cand.get('sig', '')[:60]}: {err}")
                return
            with cache_lock:
                cache_s2[s2_key] = {'prompt_version': PROMPT_VERSION_S2, 'model': args.model, 'classification': s2_cls, 'reasoning': s2_reason, 'raw_response': s2_raw, 'updated_at': int(time.time())}
        fref['classification_stage2'] = s2_cls
        fref['reasoning_stage2'] = s2_reason
        fref['classification'] = s2_cls
        fref['reasoning'] = s2_reason
        with state_lock:
            n_done += 1
    completed = 0
    if args.workers <= 1:
        for i, w in enumerate(work, start=1):
            process_one(i, w)
            completed += 1
            if completed % args.save_every == 0 or completed == len(work):
                with cache_lock:
                    s1_snap = dict(cache_s1)
                    s2_snap = dict(cache_s2)
                with flush_lock:
                    save_json_cache(args.cache_json_s1, s1_snap)
                    save_json_cache(args.cache_json_s2, s2_snap)
                    flush_jsonl()
                with state_lock:
                    elapsed = time.time() - t0
                    print(f'  [{completed}/{len(work)}] done  s1_hit={n_s1_hits} s1_llm={n_s1_calls} s2_hit={n_s2_hits} s2_llm={n_s2_calls} err={n_error} (s1 inc={n_s1_incidental} rel={n_s1_related})  elapsed={elapsed:.1f}s')
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(process_one, i, w) for i, w in enumerate(work, start=1)]
            for fut in as_completed(futures):
                _ = fut.result()
                completed += 1
                if completed % args.save_every == 0 or completed == len(work):
                    with cache_lock:
                        s1_snap = dict(cache_s1)
                        s2_snap = dict(cache_s2)
                    with flush_lock:
                        save_json_cache(args.cache_json_s1, s1_snap)
                        save_json_cache(args.cache_json_s2, s2_snap)
                        flush_jsonl()
                    with state_lock:
                        elapsed = time.time() - t0
                        rate = completed / max(1, elapsed)
                        eta = (len(work) - completed) / max(1e-06, rate)
                        print(f'  [{completed}/{len(work)}] done  s1_hit={n_s1_hits} s1_llm={n_s1_calls} s2_hit={n_s2_hits} s2_llm={n_s2_calls} err={n_error} (s1 inc={n_s1_incidental} rel={n_s1_related})  elapsed={elapsed:.1f}s rate={rate:.2f}/s eta={eta / 60:.1f}min')
    elapsed = time.time() - t0
    print(f'\n[done] processed {n_done}/{len(work)} funcs in {elapsed:.1f}s')
    print(f'  Stage 1: cache_hit={n_s1_hits}  llm={n_s1_calls}  (incidental={n_s1_incidental}  related={n_s1_related})')
    print(f'  Stage 2: cache_hit={n_s2_hits}  llm={n_s2_calls}  (skipped {n_s1_incidental} incidental funcs)')
    print(f'  errors: {n_error}')
    print(f'[output] {args.output_jsonl}')
    print(f'[cache S1] {args.cache_json_s1}  ({len(cache_s1)} entries)')
    print(f'[cache S2] {args.cache_json_s2}  ({len(cache_s2)} entries)')
if __name__ == '__main__':
    main()
