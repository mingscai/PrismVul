#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
try:
    from openai import OpenAI
except Exception:
    OpenAI = None
try:
    import anthropic as anthropic_sdk
except Exception:
    anthropic_sdk = None
try:
    from tqdm import tqdm
except Exception:
    tqdm = None
PROMPT_VERSION = '7_4_v1'
DEFAULT_INPUT = Path('data/processing/chromium_cve_data.jsonl')
DEFAULT_OUTPUT = Path('data/processing/chromium_cve_data.with_issue_summary.jsonl')
DEFAULT_CACHE = Path('cache/issue_summary_cache.json')
SYSTEM_PROMPT = 'You are a careful security analyst. Your task is to produce a concise technical issue summary of a reported software system vulnerability based only on the given information.\n\nINPUT:\n- Issue description\n- Relevant comments (chronological, ending with the last fix-related comment)\n\nGOAL:\nWrite a pre-fix style technical issue summary for maintainers.\nThe summary should describe the vulnerability itself, not the patch history or workflow state.\n\nINSTRUCTIONS:\n1. Combine the description and relevant comments into a single coherent summary.\n2. Prefer later comments only when they add, confirm, or correct technical facts about the vulnerability trigger, mechanism, affected scope, impact, or necessary safety condition.\n3. Focus only on security-relevant content, when explicitly supported by the input:\n   - vulnerability nature or failure mode\n   - trigger or attack scenario\n   - affected platform or version scope\n   - observed or plausibly confirmed security impact\n   - technical mechanism of the issue\n   - necessary safety condition or correctness constraint, if later comments clarify it\n4. Strictly exclude:\n   - function names, method names, variable names, method-call expressions\n   - file paths, commit hashes, line numbers\n   - source code snippets\n   - URLs, links, embedded resource locations, proof-of-concept links, and download links\n   - empty comments, migration artifacts, bot messages, closure notices\n   - process or management details (e.g., severity ratings, code review notes, merge status, approval workflow, rollouts, approvals, backports)\n5. High-level technical location names may be retained when they help explain the vulnerability without exposing exact implementation details. These may include modules, subsystems, namespaces, classes, rendering paths, readback paths, or other component-level names supported by the text.\n6. When low-level identifiers appear, replace them with the closest higher-level technical description supported by the surrounding text. Do not over-generalize.\n7. Collapse multiple implementation observations into a compact technical summary when they describe the same issue mechanism.\n8. If early comments suggest a misleading crash location or symptom, but later comments clarify the likely mechanism or source of corruption, summarize the later clarified mechanism rather than the earlier misleading location.\n9. If later comments clarify the technical condition needed to avoid the issue, you may restate that condition as a concise safety requirement or correctness constraint. Do not describe it as a landed patch or completed fix.\n10. Prefer neutral technical wording such as:\n    - "X should be enforced"\n    - "Y must remain consistent"\n    - "Z should avoid ..."\n    rather than patch-history wording such as:\n    - "the fix enforces X"\n    - "the patch changes Y"\n    - "this was fixed by Z"\n11. Any safety requirement or correctness constraint you mention must be directly supported by the issue description or comments, and must not introduce new technical details beyond what the thread supports.\n\nSTYLE:\n- Write a concise technical paragraph, typically 3-6 sentences depending on issue complexity.\n- Use fewer sentences for simple issues and more sentences only when needed to preserve distinct technical points.\n- Each sentence should convey one main technical point.\n- Use clear, factual, technical language in the style of a vulnerability report.\n- Retain original security terminology when useful.\n- Avoid speculation, filler, narrative explanations, and retrospective patch language.\n- Do not over-compress distinct technical facts into a single vague sentence.\n- Treat the output as a pre-fix technical issue report, not a post-fix retrospective summary.\n\nOUTPUT:\nA single paragraph summarizing the issue, with enough detail to preserve all distinct security-relevant technical points explicitly supported by the input.\n\nDO NOT add extra words or context.\n'
OUTPUT_JSON_SCHEMA = {'type': 'object', 'properties': {'summary': {'type': 'string'}}, 'required': ['summary'], 'additionalProperties': False}

def format_entry(info: dict[str, Any]) -> str:
    text = str(info.get('content', '')).strip()
    text = text.replace('\n', '\n    ')
    return f"- [{info.get('time', '')}] {info.get('creator', '')}: {text}"

def build_issue_prompt(issue: dict[str, Any]) -> str:
    title = issue.get('title', '')
    content = issue.get('content', {})
    description = content.get('description', {})
    comments = content.get('comments', [])
    cutoff_idx = None
    for i, c in enumerate(comments):
        if c.get('has_commit_id', False):
            cutoff_idx = i
    if cutoff_idx is not None:
        comments = comments[:cutoff_idx + 1]
    desc_str = format_entry(description) if description else '(no description)'
    comments_str = '\n'.join((format_entry(c) for c in comments)) if comments else '(no comments)'
    return f'---\nIssue Title: {title}\n---\nIssue Description:\n{desc_str}\n---\nIssue Comments:\n{comments_str}\n---\nPlease summarize the above issue report in the style of a vulnerability report: concise, precise, factual, and technical.'

@dataclass
class CallResult:
    ok: bool
    summary: str | None
    attempts: int
    raw_content: str
    usage: dict[str, int | None]
    error: str | None

def parse_summary(raw: str, use_structured_output: bool) -> str:
    if not use_structured_output:
        return raw.strip()
    text = re.sub('^```[a-zA-Z]*\\s*', '', raw.strip())
    text = re.sub('\\s*```$', '', text)
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get('summary'), str):
            return obj['summary'].strip()
    except Exception:
        pass
    m = re.search('"summary"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"', text)
    if m:
        return json.loads(f'"{m.group(1)}"').strip()
    raise ValueError(f'Cannot parse summary from: {raw[:200]!r}')

def flush_and_sync(fh) -> None:
    fh.flush()
    os.fsync(fh.fileno())

def default_meta_path(output_jsonl: Path) -> Path:
    return output_jsonl.with_suffix(output_jsonl.suffix + '.meta.jsonl')

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

def recover_jsonl_prefix(path: Path) -> tuple[int, bool]:
    if not path.exists() or not path.is_file():
        return (0, False)
    kept = 0
    truncated = False
    last_good_pos = 0
    with path.open('rb+') as f:
        while True:
            line = f.readline()
            if not line:
                break
            stripped = line.strip()
            if not stripped:
                last_good_pos = f.tell()
                continue
            try:
                json.loads(stripped)
                kept += 1
                last_good_pos = f.tell()
            except json.JSONDecodeError:
                truncated = True
                break
        if truncated:
            f.truncate(last_good_pos)
    return (kept, truncated)

def ensure_trailing_newline(path: Path) -> None:
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open('rb+') as f:
        f.seek(-1, 2)
        if f.read(1) != b'\n':
            f.write(b'\n')

def count_nonempty_jsonl_records(path: Path) -> int:
    if not path.exists() or not path.is_file():
        return 0
    count = 0
    with path.open('r', encoding='utf-8') as f:
        for raw in f:
            if raw.strip():
                count += 1
    return count

def truncate_jsonl_to_record_count(path: Path, n: int) -> None:
    if not path.exists():
        return
    kept = 0
    cutoff = 0
    with path.open('rb') as f:
        while kept < n:
            line = f.readline()
            if not line:
                break
            if line.strip():
                kept += 1
            cutoff = f.tell()
    with path.open('rb+') as f:
        f.seek(cutoff)
        f.truncate()

def iter_nonempty_jsonl(path: Path):
    with path.open('r', encoding='utf-8') as f:
        for raw in f:
            if raw.strip():
                yield raw

def cve_record_key(record: dict[str, Any], line_no: int) -> str:
    for key in ('cve_id', 'cve', 'id'):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return f'line:{line_no}'

def backfill_meta_from_output(output_jsonl: Path, meta_handle, *, start_record: int, model: str) -> int:
    written = 0
    for idx, raw in enumerate(iter_nonempty_jsonl(output_jsonl), start=1):
        if idx < start_record:
            continue
        record = json.loads(raw)
        if not isinstance(record, dict):
            continue
        issues = record.get('issues') or []
        n_issues = len(issues)
        n_summarized = sum((1 for iss in issues if isinstance(iss.get('summary'), str)))
        row = {'line_no': idx, 'record_key': cve_record_key(record, idx), 'status': 'backfilled_from_output', 'model': model, 'prompt_version': PROMPT_VERSION, 'n_issues': n_issues, 'n_summarized': n_summarized, 'cache_hit': None, 'attempts': None, 'elapsed_ms': None, 'usage': None, 'error': None}
        meta_handle.write(json.dumps(row, ensure_ascii=False) + '\n')
        written += 1
    return written

def print_demo_prompt(input_jsonl: Path) -> None:
    import random
    chosen: tuple[str, dict[str, Any]] | None = None
    seen = 0
    for line_no, raw in enumerate(iter_nonempty_jsonl(input_jsonl), start=1):
        try:
            record = json.loads(raw)
        except Exception:
            continue
        issues = record.get('issues') or []
        for issue in issues:
            if issue.get('content'):
                seen += 1
                if random.randrange(seen) == 0:
                    chosen = (cve_record_key(record, line_no), issue)
    if chosen is None:
        raise SystemExit(f'No records with issues in: {input_jsonl}')
    cve_id, issue = chosen
    print('=== 7_4 demo prompt ===')
    print(f'Input path: {input_jsonl}')
    print(f'CVE ID:     {cve_id}')
    print(f"Issue ID:   {issue.get('issue_id', '?')}")
    print('--- SYSTEM ---')
    print(SYSTEM_PROMPT)
    print('--- USER ---')
    print(build_issue_prompt(issue))

def is_empty_issue(issue: dict[str, Any]) -> bool:
    content = issue.get('content') or {}
    desc = content.get('description') or {}
    desc_text = (desc.get('content') or '').strip() if isinstance(desc, dict) else ''
    comments = content.get('comments') or []
    has_comment = any(((c.get('content') or '').strip() for c in comments if isinstance(c, dict)))
    return not desc_text and (not has_comment)

def issue_identifier(issue: dict[str, Any], idx: int) -> str:
    issue_id = str(issue.get('issue_id', '')).strip()
    if issue_id:
        return issue_id
    link = str(issue.get('link', '')).strip()
    if link:
        return link.rstrip('/').split('/')[-1]
    return str(idx)

def build_cache_key(*, issue: dict[str, Any], idx: int) -> str:
    h = hashlib.sha256()
    h.update(PROMPT_VERSION.encode('utf-8'))
    h.update(b'\n')
    h.update(issue_identifier(issue, idx).encode('utf-8'))
    return h.hexdigest()

def call_anthropic(*, client: Any, model: str, issue: dict[str, Any], max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool) -> CallResult:
    last_error: str | None = None
    last_content = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_issue_prompt(issue)
        try:
            create_kwargs: dict[str, Any] = dict(model=model, max_tokens=max_tokens, system=SYSTEM_PROMPT, messages=[{'role': 'user', 'content': user_prompt}])
            if use_structured_output:
                create_kwargs['output_config'] = {'format': {'type': 'json_schema', 'schema': OUTPUT_JSON_SCHEMA}}
            with client.messages.stream(**create_kwargs) as stream:
                response = stream.get_final_message()
            content = ''
            for block in response.content:
                if getattr(block, 'type', None) == 'text':
                    content = getattr(block, 'text', '').strip()
            ru = getattr(response, 'usage', None)
            last_usage = {'prompt_tokens': getattr(ru, 'input_tokens', None), 'completion_tokens': getattr(ru, 'output_tokens', None), 'total_tokens': (getattr(ru, 'input_tokens', 0) or 0) + (getattr(ru, 'output_tokens', 0) or 0) if ru else None, 'reasoning_tokens': None}
            if not content:
                raise ValueError('empty response')
            summary = parse_summary(content, use_structured_output)
            return CallResult(ok=True, summary=summary, attempts=attempt, raw_content=content, usage=last_usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_usage = locals().get('last_usage', last_usage)
            if attempt < max_retries:
                time.sleep(retry_initial_sleep * 2 ** (attempt - 1))
    return CallResult(ok=False, summary=None, attempts=max_retries, raw_content=last_content, usage=last_usage, error=last_error)

def call_openai_compatible(*, client: Any, model: str, issue: dict[str, Any], max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool, is_gpt_model: bool) -> CallResult:
    last_error: str | None = None
    last_content = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_issue_prompt(issue)
        try:
            tokens_key = 'max_completion_tokens' if is_gpt_model else 'max_tokens'
            create_kwargs: dict[str, Any] = {'model': model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}], tokens_key: max_tokens}
            if use_structured_output:
                if is_gpt_model:
                    create_kwargs['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'issue_summary', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
                else:
                    create_kwargs['response_format'] = {'type': 'json_object'}
            response = client.chat.completions.create(**create_kwargs)
            choice = response.choices[0].message
            content = (getattr(choice, 'content', '') or '').strip()
            ru = getattr(response, 'usage', None)
            last_usage = {'prompt_tokens': getattr(ru, 'prompt_tokens', None), 'completion_tokens': getattr(ru, 'completion_tokens', None), 'total_tokens': getattr(ru, 'total_tokens', None), 'reasoning_tokens': getattr(getattr(ru, 'completion_tokens_details', None), 'reasoning_tokens', None)}
            if not content:
                raise ValueError('empty response')
            summary = parse_summary(content, use_structured_output)
            return CallResult(ok=True, summary=summary, attempts=attempt, raw_content=content, usage=last_usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_usage = locals().get('last_usage', last_usage)
            if attempt < max_retries:
                time.sleep(retry_initial_sleep * 2 ** (attempt - 1))
    return CallResult(ok=False, summary=None, attempts=max_retries, raw_content=last_content, usage=last_usage, error=last_error)

def build_openai_batch_item(*, cve_id: str, input_line_no: int, issue: dict[str, Any], issue_idx: int, model: str, max_tokens: int, use_structured_output: bool) -> dict[str, Any]:
    uid = issue_identifier(issue, issue_idx)
    user_prompt = build_issue_prompt(issue)
    body: dict[str, Any] = {'model': model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}], 'max_completion_tokens': max_tokens}
    if use_structured_output:
        body['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'issue_summary', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
    return {'custom_id': f'{cve_id}::ISSUE-{uid}::{input_line_no}', 'method': 'POST', 'url': '/v1/chat/completions', 'body': body}

def build_meta_row(*, line_no: int, record: dict[str, Any], model: str, status: str, n_issues: int, n_summarized: int, n_errors: int, cache_hits: int, total_attempts: int, elapsed_ms: int, aggregated_usage: dict[str, Any], last_error: str | None) -> dict[str, Any]:
    return {'line_no': line_no, 'record_key': cve_record_key(record, line_no), 'status': status, 'model': model, 'prompt_version': PROMPT_VERSION, 'n_issues': n_issues, 'n_summarized': n_summarized, 'n_errors': n_errors, 'cache_hits': cache_hits, 'total_attempts': total_attempts, 'elapsed_ms': elapsed_ms, 'usage': aggregated_usage, 'error': last_error}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Summarize Chromium issue content for CVE records')
    parser.add_argument('--input-jsonl', type=Path, default=DEFAULT_INPUT)
    parser.add_argument('--output-jsonl', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--meta-out', type=Path, default=None, help='Metadata JSONL path (default: <output>.meta.jsonl)')
    parser.add_argument('--model', type=str, default='claude-sonnet-4-6', help="Model name: 'claude' → Anthropic SDK; 'deepseek'/'gpt' → OpenAI SDK")
    parser.add_argument('--base-url', type=str, default=None, help='API base URL override (DeepSeek default: https://api.deepseek.com/v1)')
    parser.add_argument('--api-key', type=str, default=None, help='API key (fallback: ANTHROPIC_API_KEY / DEEPSEEK_API_KEY / OPENAI_API_KEY)')
    parser.add_argument('--structured-output', action='store_true', help='Use provider structured output / json_schema mode (output: {"summary": "..."})')
    parser.add_argument('--batch-api', action='store_true', help='GPT only: write OpenAI Batch request JSONL to output instead of calling API')
    parser.add_argument('--cache-json', type=Path, default=DEFAULT_CACHE)
    parser.add_argument('--max-tokens', type=int, default=512, help='Max output tokens per LLM call')
    parser.add_argument('--max-retries', type=int, default=3)
    parser.add_argument('--retry-initial-sleep', type=float, default=2.0)
    parser.add_argument('--delay', type=float, default=0.0)
    parser.add_argument('--save-every', type=int, default=20)
    parser.add_argument('--max-records', type=int, default=0, help='Max new input records to process (0 = all)')
    parser.add_argument('--strict-errors', action='store_true')
    parser.add_argument('--demo-prompt', action='store_true', help='Print a random system+user prompt example and exit')
    parser.add_argument('--no-progress', action='store_true')
    parser.add_argument('--overwrite', action='store_true')
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    if not args.input_jsonl.exists():
        raise SystemExit(f'Input not found: {args.input_jsonl}')
    if args.demo_prompt:
        print_demo_prompt(args.input_jsonl)
        return
    model_lower = args.model.lower()
    is_anthropic = 'claude' in model_lower
    is_deepseek = 'deepseek' in model_lower
    is_gpt = 'gpt' in model_lower
    if not is_anthropic and (not is_deepseek) and (not is_gpt):
        raise SystemExit(f"Cannot detect provider from model '{args.model}'. Name must contain 'claude', 'deepseek', or 'gpt'.")
    if not args.base_url and is_deepseek:
        args.base_url = 'https://api.deepseek.com/v1'
    batch_mode_active = bool(args.batch_api and is_gpt)
    if args.batch_api and (not is_gpt):
        print('[7_4] --batch-api ignored (model is not GPT)')
    client: Any = None
    if not batch_mode_active:
        if args.api_key:
            api_key = args.api_key
        else:
            env_var = 'ANTHROPIC_API_KEY' if is_anthropic else 'DEEPSEEK_API_KEY' if is_deepseek else 'OPENAI_API_KEY'
            api_key = os.environ.get(env_var)
            if not api_key:
                raise EnvironmentError(f'API key not found. Provide --api-key or set {env_var}.')
        if is_anthropic:
            if anthropic_sdk is None:
                raise EnvironmentError('pip install anthropic')
            client = anthropic_sdk.Anthropic(api_key=api_key, **{'base_url': args.base_url} if args.base_url else {})
        else:
            if OpenAI is None:
                raise EnvironmentError('pip install openai')
            ck: dict[str, Any] = {'api_key': api_key}
            if args.base_url:
                ck['base_url'] = args.base_url
            client = OpenAI(**ck)
    meta_out = args.meta_out or default_meta_path(args.output_jsonl)
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    meta_out.parent.mkdir(parents=True, exist_ok=True)
    total_records = count_nonempty_jsonl_records(args.input_jsonl)
    if total_records <= 0:
        raise SystemExit(f'No records in input: {args.input_jsonl}')
    if args.overwrite:
        args.output_jsonl.unlink(missing_ok=True)
        meta_out.unlink(missing_ok=True)
    output_records = meta_records = 0
    output_truncated = meta_truncated = False
    meta_backfilled = 0
    if not batch_mode_active:
        if args.output_jsonl.exists():
            output_records, output_truncated = recover_jsonl_prefix(args.output_jsonl)
            ensure_trailing_newline(args.output_jsonl)
        if meta_out.exists():
            meta_records, meta_truncated = recover_jsonl_prefix(meta_out)
            ensure_trailing_newline(meta_out)
        if meta_records > output_records:
            truncate_jsonl_to_record_count(meta_out, output_records)
            meta_records = output_records
        if meta_records < output_records:
            with meta_out.open('a', encoding='utf-8') as fmeta_bf:
                meta_backfilled = backfill_meta_from_output(args.output_jsonl, fmeta_bf, start_record=meta_records + 1, model=args.model)
                flush_and_sync(fmeta_bf)
            meta_records += meta_backfilled
    resumed_records = output_records if not batch_mode_active else 0
    if resumed_records > total_records:
        raise SystemExit(f'Output has more rows than input. Use --overwrite. output={resumed_records}, input={total_records}')
    cache = {} if batch_mode_active else load_json_cache(args.cache_json)
    pending_total = total_records - resumed_records
    if args.max_records > 0:
        pending_total = min(pending_total, args.max_records)
    print(f'Input records:   {total_records:,}')
    print(f'Output path:     {args.output_jsonl}')
    print(f'Meta path:       {meta_out}')
    print(f"Cache path:      {args.cache_json}{(' (unused)' if batch_mode_active else '')}")
    print(f'Model:           {args.model}')
    print(f"Mode:            {('gpt_batch_prepare' if batch_mode_active else 'online_inference')}")
    print(f'Prompt version:  {PROMPT_VERSION}')
    print(f'Resume records:  {resumed_records:,}')
    print(f'Pending records: {pending_total:,}')
    if output_truncated:
        print('[7_4] Recovered output from a partial trailing line')
    if meta_truncated:
        print('[7_4] Recovered meta from a partial trailing line')
    if meta_backfilled:
        print(f'[7_4] Backfilled meta rows from output: {meta_backfilled:,}')
    write_mode = 'a' if not batch_mode_active and resumed_records > 0 else 'w'
    stats = {'processed_new': 0, 'api_calls': 0, 'cache_hits': 0, 'batch_items': 0, 'passthrough': 0, 'errors': 0}
    with args.output_jsonl.open(write_mode, encoding='utf-8') as fout, meta_out.open(write_mode, encoding='utf-8') as fmeta:
        pbar = None
        if not args.no_progress and tqdm is not None:
            pbar = tqdm(total=pending_total, desc='7_4 issues')
        newly_written = 0
        for input_line_no, raw in enumerate(iter_nonempty_jsonl(args.input_jsonl), start=1):
            if not batch_mode_active and input_line_no <= resumed_records:
                continue
            if args.max_records > 0 and stats['processed_new'] >= args.max_records:
                break
            record = json.loads(raw)
            if not isinstance(record, dict):
                continue
            cve_id = cve_record_key(record, input_line_no)
            issues = record.get('issues') or []
            start_ts = time.time()
            if not issues:
                if not batch_mode_active:
                    fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                meta_row = {'line_no': input_line_no, 'record_key': cve_id, 'status': 'passthrough_no_issues', 'model': args.model, 'prompt_version': PROMPT_VERSION, 'n_issues': 0, 'n_summarized': 0, 'n_errors': 0, 'cache_hits': 0, 'total_attempts': 0, 'elapsed_ms': 0, 'usage': None, 'error': None}
                fmeta.write(json.dumps(meta_row, ensure_ascii=False) + '\n')
                stats['processed_new'] += 1
                stats['passthrough'] += 1
                if pbar is not None:
                    pbar.update(1)
                continue
            if batch_mode_active:
                for issue_idx, issue in enumerate(issues):
                    if is_empty_issue(issue):
                        continue
                    batch_item = build_openai_batch_item(cve_id=cve_id, input_line_no=input_line_no, issue=issue, issue_idx=issue_idx, model=args.model, max_tokens=args.max_tokens, use_structured_output=args.structured_output)
                    fout.write(json.dumps(batch_item, ensure_ascii=False) + '\n')
                    stats['batch_items'] += 1
                meta_row = {'line_no': input_line_no, 'record_key': cve_id, 'status': 'batch_prepared', 'model': args.model, 'prompt_version': PROMPT_VERSION, 'n_issues': len(issues), 'n_summarized': 0, 'n_errors': 0, 'cache_hits': 0, 'total_attempts': 0, 'elapsed_ms': int((time.time() - start_ts) * 1000), 'usage': None, 'error': None}
                fmeta.write(json.dumps(meta_row, ensure_ascii=False) + '\n')
                stats['processed_new'] += 1
                newly_written += 1
                if pbar is not None:
                    pbar.update(1)
                if newly_written % args.save_every == 0:
                    flush_and_sync(fout)
                    flush_and_sync(fmeta)
                continue
            n_summarized = 0
            n_errors = 0
            rec_cache_hits = 0
            total_attempts = 0
            last_error: str | None = None
            agg_usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'reasoning_tokens': 0}
            updated_issues = []
            for issue_idx, issue in enumerate(issues):
                if is_empty_issue(issue):
                    updated_issue = dict(issue)
                    updated_issue['summary'] = None
                    updated_issues.append(updated_issue)
                    continue
                cache_key = build_cache_key(issue=issue, idx=issue_idx)
                cache_entry = cache.get(cache_key)
                if isinstance(cache_entry, dict) and isinstance(cache_entry.get('summary'), str):
                    call_result = CallResult(ok=True, summary=cache_entry['summary'], attempts=0, raw_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                    rec_cache_hits += 1
                    stats['cache_hits'] += 1
                else:
                    if is_anthropic:
                        call_result = call_anthropic(client=client, model=args.model, issue=issue, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output)
                    else:
                        call_result = call_openai_compatible(client=client, model=args.model, issue=issue, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output, is_gpt_model=is_gpt)
                    stats['api_calls'] += 1
                    if call_result.ok and call_result.summary:
                        cache[cache_key] = {'prompt_version': PROMPT_VERSION, 'model': args.model, 'summary': call_result.summary, 'updated_at': int(time.time())}
                    if args.delay > 0:
                        time.sleep(args.delay)
                total_attempts += call_result.attempts
                for k in ('prompt_tokens', 'completion_tokens', 'total_tokens', 'reasoning_tokens'):
                    v = (call_result.usage or {}).get(k)
                    if isinstance(v, int):
                        agg_usage[k] = (agg_usage[k] or 0) + v
                updated_issue = dict(issue)
                if call_result.ok and call_result.summary:
                    updated_issue['summary'] = call_result.summary
                    n_summarized += 1
                else:
                    n_errors += 1
                    last_error = call_result.error
                    stats['errors'] += 1
                    if args.strict_errors:
                        raise RuntimeError(f'LLM failed at {cve_id} issue {issue_identifier(issue, issue_idx)}: {call_result.error}')
                updated_issues.append(updated_issue)
            elapsed_ms = int((time.time() - start_ts) * 1000)
            status = 'processed' if n_errors == 0 else 'partial_error'
            out_record = dict(record)
            out_record['issues'] = updated_issues
            fout.write(json.dumps(out_record, ensure_ascii=False) + '\n')
            meta_row = build_meta_row(line_no=input_line_no, record=record, model=args.model, status=status, n_issues=len(issues), n_summarized=n_summarized, n_errors=n_errors, cache_hits=rec_cache_hits, total_attempts=total_attempts, elapsed_ms=elapsed_ms, aggregated_usage=agg_usage, last_error=last_error)
            fmeta.write(json.dumps(meta_row, ensure_ascii=False) + '\n')
            stats['processed_new'] += 1
            newly_written += 1
            if pbar is not None:
                pbar.update(1)
            if newly_written % args.save_every == 0:
                flush_and_sync(fout)
                flush_and_sync(fmeta)
                save_json_cache(args.cache_json, cache)
        if pbar is not None:
            pbar.close()
        flush_and_sync(fout)
        flush_and_sync(fmeta)
        if not batch_mode_active:
            save_json_cache(args.cache_json, cache)
    final_out = count_nonempty_jsonl_records(args.output_jsonl)
    final_meta = count_nonempty_jsonl_records(meta_out)
    print('=== 7_4 done ===')
    print(f'Output rows:        {final_out:,}')
    print(f'Meta rows:          {final_meta:,}')
    print(f"Newly processed:    {stats['processed_new']:,}")
    if batch_mode_active:
        print(f"Batch items:        {stats['batch_items']:,}")
    else:
        print(f"API calls:          {stats['api_calls']:,}")
        print(f"Cache hits:         {stats['cache_hits']:,}")
        print(f"Passthrough:        {stats['passthrough']:,}")
        print(f"Errors:             {stats['errors']:,}")
    print(f'Output path:        {args.output_jsonl}')
    print(f'Meta path:          {meta_out}')
if __name__ == '__main__':
    main()
