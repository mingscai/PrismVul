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
PROMPT_VERSION = '7_2_v1'
DEFAULT_INPUT = Path('data/processing/chromium_cve_data.cve_desc_masked.jsonl')
DEFAULT_OUTPUT = Path('data/processing/chromium_cve_data.cve_desc_restated.jsonl')
DEFAULT_CACHE = Path('cache/cve_desc_restated_cache.json')
PLACEHOLDER_RE = re.compile('<(?:FUNC|FILE|SOFTWARE_VERSION|OS_VERSION)>')
OUTPUT_JSON_SCHEMA = {'type': 'object', 'properties': {'restated_desc': {'type': 'string'}}, 'required': ['restated_desc'], 'additionalProperties': False}
SYSTEM_PROMPT = 'You are a security-text editor.\n\nTASK:\nYou receive a CVE description where certain implementation-location and environment hints have been replaced with placeholders:\n  <FUNC>             — a function or method name\n  <FILE>             — a source file path or filename\n  <SOFTWARE_VERSION> — a software version number or range\n  <OS_VERSION>       — an OS/platform version number\n\nYour task is to restate the description by removing all placeholder tokens and restoring grammatical coherence with minimal edits.\n\nThis is a deletion-and-repair task, not a paraphrasing or summarization task.\n\nRULES:\n1. Remove placeholder tokens and the minimal surrounding phrasing needed to restore natural flow.\n2. Prefer deleting the smallest contiguous phrase that directly depends on a placeholder, rather than rewriting the whole sentence.\n3. Preserve all non-placeholder content exactly as much as possible.\n   - Do not paraphrase.\n   - Do not substitute synonyms.\n   - Do not reorder facts.\n   - Do not summarize.\n   - Do not add any information not present in the input.\n4. After removing placeholders, make only the smallest grammatical or punctuation repairs necessary for the sentence to read naturally.\n5. If removing placeholder-dependent text leaves a clear grammatical subject and predicate, do not further rewrite the sentence.\n6. Do not invent generic stand-ins such as "a certain function", "a specific file", "a vulnerable component", or similar wording unless that wording is directly supported by the remaining text.\n7. Preserve parenthetical notes, severity labels, and trailing metadata unless they themselves contain placeholder tokens.\n8. If a sentence becomes awkward because its subject or object was entirely placeholder, reconstruct it minimally using only the remaining context.\n9. Remove all placeholder tokens from the final output. The final restated_desc must not contain <FUNC>, <FILE>, <SOFTWARE_VERSION>, or <OS_VERSION>.\n\nCommon patterns to collapse:\n- "before <SOFTWARE_VERSION>" / "prior to <SOFTWARE_VERSION>" → remove the whole phrase\n- "<SOFTWARE_VERSION> and earlier" → remove the whole phrase\n- "<SOFTWARE_VERSION> through <SOFTWARE_VERSION>" → remove the whole span\n- "the <FUNC> function in <FILE> in" → remove the whole locator phrase\n- "the <FUNC> function in <FILE>" → remove the whole locator phrase\n- "in <FILE>" → remove "in <FILE>"\n- "Windows <OS_VERSION>" / "Android <OS_VERSION>" / "iOS <OS_VERSION>" / "macOS <OS_VERSION>" → remove only the <OS_VERSION> token and keep the OS name\n- "<OS_VERSION> and <OS_VERSION>" (bare version list) → remove the whole list\n\nOUTPUT:\nReturn a single JSON object with one key:\n{"restated_desc": "the restated description"}\n\nReturn JSON only. No markdown. No extra keys.\n\nEXAMPLES:\n\n[Example 1]\nInput:\nUse-after-free vulnerability in the <FUNC> function in <FILE> in the Extensions implementation in Google Chrome before <SOFTWARE_VERSION> allows remote attackers to cause a denial of service or possibly have unspecified other impact via crafted JavaScript code that modifies a pointer used for reporting loadTimes data.\nOutput json:\n{"restated_desc":"Use-after-free vulnerability in the Extensions implementation in Google Chrome allows remote attackers to cause a denial of service or possibly have unspecified other impact via crafted JavaScript code that modifies a pointer used for reporting loadTimes data."}\n\n[Example 2]\nInput:\nThe <FUNC> function in <FILE> in Google Chrome before <SOFTWARE_VERSION> does not initialize the memory locations that will hold bitmap data, which might allow remote attackers to obtain potentially sensitive information from process memory by providing insufficient data, related to use of a (1) thumbnail database or (2) HTML canvas.\nOutput json:\n{"restated_desc":"Google Chrome does not initialize the memory locations that will hold bitmap data, which might allow remote attackers to obtain potentially sensitive information from process memory by providing insufficient data, related to use of a (1) thumbnail database or (2) HTML canvas."}\n\n[Example 3]\nInput:\nInteger overflow in Skia in Google Chrome prior to <SOFTWARE_VERSION> allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)\nOutput json:\n{"restated_desc":"Integer overflow in Skia in Google Chrome allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)"}\n\n[Example 4]\nInput:\nA vulnerability in Google Chrome on Windows <OS_VERSION> and Android <OS_VERSION> may allow remote attackers to cause a denial of service.\nOutput json:\n{"restated_desc":"A vulnerability in Google Chrome on Windows and Android may allow remote attackers to cause a denial of service."}\n\n[Example 5]\nInput:\nUnspecified vulnerability in Adobe Flash Player <SOFTWARE_VERSION> and earlier allows remote attackers to execute arbitrary code via unknown vectors, as exploited in the wild in June 2016.\nOutput json:\n{"restated_desc":"Unspecified vulnerability in Adobe Flash Player allows remote attackers to execute arbitrary code via unknown vectors, as exploited in the wild in June 2016."}\n\n[Example 6]\nInput:\nUnspecified vulnerability in Adobe Flash Player <SOFTWARE_VERSION> and earlier, as used in the Adobe Flash libraries in Microsoft Internet Explorer <OS_VERSION> and <OS_VERSION> and Microsoft Edge, has unknown impact and attack vectors.\nOutput json:\n{"restated_desc":"Unspecified vulnerability in Adobe Flash Player, as used in the Adobe Flash libraries in Microsoft Internet Explorer and Microsoft Edge, has unknown impact and attack vectors."}\n\n[Example 7]\nInput:\nUse-after-free in <FUNC> allowed a remote attacker to cause a denial of service via a crafted HTML page.\nOutput json:\n{"restated_desc":"Use-after-free allowed a remote attacker to cause a denial of service via a crafted HTML page."}\n\n[Example 8]\nInput:\nA vulnerability in the <FUNC> function in <FILE> in the V8 engine in Google Chrome before <SOFTWARE_VERSION> may allow remote attackers to execute arbitrary code.\nOutput json:\n{"restated_desc":"A vulnerability in the V8 engine in Google Chrome may allow remote attackers to execute arbitrary code."}\n\nReturn json only. No markdown. No extra keys.\n'

@dataclass
class CallResult:
    ok: bool
    restated_desc: str
    attempts: int
    raw_content: str
    usage: dict[str, int | None]
    error: str | None

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
        desc_masked = str(record.get('cve_desc_masked') or '')
        restated = str(record.get('cve_desc_restated') or desc_masked)
        row = {'line_no': idx, 'record_key': cve_record_key(record, idx), 'status': 'backfilled_from_output', 'model': model, 'prompt_version': PROMPT_VERSION, 'restated': restated != desc_masked, 'cache_hit': None, 'attempts': None, 'elapsed_ms': None, 'usage': None, 'error': None}
        meta_handle.write(json.dumps(row, ensure_ascii=False) + '\n')
        written += 1
    return written

def print_demo_prompt(input_jsonl: Path) -> None:
    import random
    chosen: tuple[str, str] | None = None
    seen = 0
    for line_no, raw in enumerate(iter_nonempty_jsonl(input_jsonl), start=1):
        try:
            record = json.loads(raw)
        except Exception:
            continue
        if not isinstance(record, dict):
            continue
        cve_desc_masked = str(record.get('cve_desc_masked') or '').strip()
        if not cve_desc_masked:
            continue
        cve_id = str(record.get('cve_id') or cve_record_key(record, line_no)).strip()
        seen += 1
        if random.randrange(seen) == 0:
            chosen = (cve_id, cve_desc_masked)
    if chosen is None:
        raise SystemExit(f'No records with cve_desc_masked in: {input_jsonl}')
    cve_id, cve_desc_masked = chosen
    print('=== 7_2 demo prompt ===')
    print(f'Input path:    {input_jsonl}')
    print(f'Sample CVE_ID: {cve_id}')
    print('--- SYSTEM ---')
    print(SYSTEM_PROMPT)
    print('--- USER ---')
    print(build_user_prompt(cve_id, cve_desc_masked))

def build_user_prompt(cve_id: str, cve_desc_masked: str) -> str:
    return f'Restate the CVE description and return json.\n\nCVE_ID: {cve_id}\n\nMASKED_DESCRIPTION_BEGIN\n{cve_desc_masked}\nMASKED_DESCRIPTION_END'

def build_cache_key(*, model: str, cve_desc_masked: str) -> str:
    h = hashlib.sha256()
    h.update(PROMPT_VERSION.encode('utf-8'))
    h.update(b'\n')
    h.update(model.encode('utf-8'))
    h.update(b'\n')
    h.update(cve_desc_masked.encode('utf-8'))
    return h.hexdigest()

def parse_restated_desc(raw: str) -> str:
    text = re.sub('^```[a-zA-Z]*\\s*', '', raw.strip())
    text = re.sub('\\s*```$', '', text)
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get('restated_desc'), str):
            return obj['restated_desc'].strip()
    except Exception:
        pass
    m = re.search('"restated_desc"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"', text)
    if m:
        return json.loads(f'"{m.group(1)}"').strip()
    raise ValueError(f'Cannot parse restated_desc from: {raw[:200]!r}')

def call_anthropic(*, client: Any, model: str, cve_id: str, cve_desc_masked: str, max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool) -> CallResult:
    last_error: str | None = None
    last_content = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_user_prompt(cve_id, cve_desc_masked)
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
            restated = parse_restated_desc(content)
            return CallResult(ok=True, restated_desc=restated, attempts=attempt, raw_content=content, usage=last_usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_usage = locals().get('last_usage', last_usage)
            if attempt < max_retries:
                time.sleep(retry_initial_sleep * 2 ** (attempt - 1))
    return CallResult(ok=False, restated_desc='', attempts=max_retries, raw_content=last_content, usage=last_usage, error=last_error)

def call_openai_compatible(*, client: Any, model: str, cve_id: str, cve_desc_masked: str, max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool, is_gpt_model: bool) -> CallResult:
    last_error: str | None = None
    last_content = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_user_prompt(cve_id, cve_desc_masked)
        try:
            tokens_key = 'max_completion_tokens' if is_gpt_model else 'max_tokens'
            create_kwargs: dict[str, Any] = {'model': model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}], tokens_key: max_tokens}
            if use_structured_output:
                if is_gpt_model:
                    create_kwargs['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'cve_desc_restated', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
                else:
                    create_kwargs['response_format'] = {'type': 'json_object'}
            response = client.chat.completions.create(**create_kwargs)
            choice = response.choices[0].message
            content = (getattr(choice, 'content', '') or '').strip()
            ru = getattr(response, 'usage', None)
            last_usage = {'prompt_tokens': getattr(ru, 'prompt_tokens', None), 'completion_tokens': getattr(ru, 'completion_tokens', None), 'total_tokens': getattr(ru, 'total_tokens', None), 'reasoning_tokens': getattr(getattr(ru, 'completion_tokens_details', None), 'reasoning_tokens', None)}
            if not content:
                raise ValueError('empty response')
            restated = parse_restated_desc(content)
            return CallResult(ok=True, restated_desc=restated, attempts=attempt, raw_content=content, usage=last_usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_usage = locals().get('last_usage', last_usage)
            if attempt < max_retries:
                time.sleep(retry_initial_sleep * 2 ** (attempt - 1))
    return CallResult(ok=False, restated_desc='', attempts=max_retries, raw_content=last_content, usage=last_usage, error=last_error)

def build_openai_batch_item(*, line_no: int, record: dict[str, Any], model: str, cve_id: str, cve_desc_masked: str, max_tokens: int, use_structured_output: bool) -> dict[str, Any]:
    user_prompt = build_user_prompt(cve_id, cve_desc_masked)
    body: dict[str, Any] = {'model': model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}], 'max_completion_tokens': max_tokens}
    if use_structured_output:
        body['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'cve_desc_restated', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
    return {'custom_id': f'{cve_record_key(record, line_no)}::{line_no}', 'method': 'POST', 'url': '/v1/chat/completions', 'body': body}

def build_meta_row(*, line_no: int, record: dict[str, Any], model: str, status: str, call_result: CallResult, cache_hit: bool, elapsed_ms: int) -> dict[str, Any]:
    return {'line_no': line_no, 'record_key': cve_record_key(record, line_no), 'status': status, 'model': model, 'prompt_version': PROMPT_VERSION, 'restated': call_result.ok and bool(call_result.restated_desc), 'cache_hit': cache_hit, 'attempts': call_result.attempts, 'elapsed_ms': elapsed_ms, 'usage': call_result.usage, 'error': call_result.error}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Restate masked CVE descriptions using an LLM')
    parser.add_argument('--input-jsonl', type=Path, default=DEFAULT_INPUT)
    parser.add_argument('--output-jsonl', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--meta-out', type=Path, default=None, help='Metadata JSONL path (default: <output>.meta.jsonl)')
    parser.add_argument('--model', type=str, default='claude-sonnet-4-6', help="Model name: 'claude' → Anthropic SDK; 'deepseek'/'gpt' → OpenAI SDK")
    parser.add_argument('--base-url', type=str, default=None, help='API base URL override (DeepSeek default: https://api.deepseek.com/v1)')
    parser.add_argument('--api-key', type=str, default=None, help='API key (fallback: ANTHROPIC_API_KEY / DEEPSEEK_API_KEY / OPENAI_API_KEY)')
    parser.add_argument('--structured-output', action='store_true', help='Use provider structured output / json_schema mode')
    parser.add_argument('--batch-api', action='store_true', help='GPT only: write OpenAI Batch request JSONL to output instead of calling API')
    parser.add_argument('--cache-json', type=Path, default=DEFAULT_CACHE)
    parser.add_argument('--max-tokens', type=int, default=1024, help='Max output tokens per LLM call')
    parser.add_argument('--max-retries', type=int, default=3)
    parser.add_argument('--retry-initial-sleep', type=float, default=2.0)
    parser.add_argument('--delay', type=float, default=0.0)
    parser.add_argument('--save-every', type=int, default=20)
    parser.add_argument('--max-records', type=int, default=0, help='Max new records to process (0 = all)')
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
    if args.max_tokens < 1:
        raise SystemExit('--max-tokens must be >= 1')
    if args.max_retries < 1:
        raise SystemExit('--max-retries must be >= 1')
    if args.save_every < 1:
        raise SystemExit('--save-every must be >= 1')
    if args.max_records < 0:
        raise SystemExit('--max-records must be >= 0')
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
        print('[7_2] --batch-api ignored (model is not GPT)')
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
    resumed_records = output_records
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
        print('[7_2] Recovered output from a partial trailing line')
    if meta_truncated:
        print('[7_2] Recovered meta from a partial trailing line')
    if meta_backfilled:
        print(f'[7_2] Backfilled meta rows from output: {meta_backfilled:,}')
    write_mode = 'a' if resumed_records > 0 else 'w'
    stats = {'processed_new': 0, 'api_calls': 0, 'cache_hits': 0, 'passthrough': 0, 'errors': 0}
    with args.output_jsonl.open(write_mode, encoding='utf-8') as fout, meta_out.open(write_mode, encoding='utf-8') as fmeta:
        pbar = None
        if not args.no_progress and tqdm is not None:
            pbar = tqdm(total=pending_total, desc='7_2 restate')
        newly_written = 0
        for input_line_no, raw in enumerate(iter_nonempty_jsonl(args.input_jsonl), start=1):
            if input_line_no <= resumed_records:
                continue
            if args.max_records > 0 and stats['processed_new'] >= args.max_records:
                break
            record = json.loads(raw)
            if not isinstance(record, dict):
                continue
            cve_id = str(record.get('cve_id') or cve_record_key(record, input_line_no))
            cve_desc_masked = str(record.get('cve_desc_masked') or '')
            meta_record = record
            start_ts = time.time()
            status = 'processed'
            cache_hit = False
            struct = record.get('cve_desc_masked_struct') or {}
            has_leakage = struct.get('has_leakage')
            need_llm = has_leakage is True or (has_leakage is None and PLACEHOLDER_RE.search(cve_desc_masked))
            if batch_mode_active and need_llm:
                record = build_openai_batch_item(line_no=input_line_no, record=record, model=args.model, cve_id=cve_id, cve_desc_masked=cve_desc_masked, max_tokens=args.max_tokens, use_structured_output=args.structured_output)
                call_result = CallResult(ok=True, restated_desc=cve_desc_masked, attempts=0, raw_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                status = 'batch_prepared'
            elif not need_llm or not cve_desc_masked.strip():
                call_result = CallResult(ok=True, restated_desc=cve_desc_masked, attempts=0, raw_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                status = 'no_leakage_passthrough'
                stats['passthrough'] += 1
            else:
                cache_key = build_cache_key(model=args.model, cve_desc_masked=cve_desc_masked)
                cache_entry = cache.get(cache_key)
                if isinstance(cache_entry, dict) and isinstance(cache_entry.get('restated_desc'), str):
                    call_result = CallResult(ok=True, restated_desc=cache_entry['restated_desc'], attempts=0, raw_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                    cache_hit = True
                    status = 'cached'
                    stats['cache_hits'] += 1
                else:
                    if is_anthropic:
                        call_result = call_anthropic(client=client, model=args.model, cve_id=cve_id, cve_desc_masked=cve_desc_masked, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output)
                    else:
                        call_result = call_openai_compatible(client=client, model=args.model, cve_id=cve_id, cve_desc_masked=cve_desc_masked, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output, is_gpt_model=is_gpt)
                    stats['api_calls'] += 1
                    if call_result.ok:
                        cache[cache_key] = {'prompt_version': PROMPT_VERSION, 'model': args.model, 'restated_desc': call_result.restated_desc, 'updated_at': int(time.time())}
                    if args.delay > 0:
                        time.sleep(args.delay)
            if not call_result.ok:
                stats['errors'] += 1
                status = 'error_passthrough'
                if args.strict_errors:
                    raise RuntimeError(f'LLM failed at line {input_line_no} ({cve_id}): {call_result.error}')
            if status == 'batch_prepared':
                write_output = True
            elif batch_mode_active:
                write_output = False
            else:
                write_output = True
                restated = call_result.restated_desc or cve_desc_masked
                ordered: dict[str, Any] = {}
                for k, v in record.items():
                    ordered[k] = v
                    if k == 'cve_desc_masked':
                        ordered['cve_desc_restated'] = restated
                if 'cve_desc_restated' not in ordered:
                    ordered['cve_desc_restated'] = restated
                record = ordered
            elapsed_ms = int((time.time() - start_ts) * 1000)
            meta_row = build_meta_row(line_no=input_line_no, record=meta_record, model=args.model, status=status, call_result=call_result, cache_hit=cache_hit, elapsed_ms=elapsed_ms)
            if write_output:
                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
            fmeta.write(json.dumps(meta_row, ensure_ascii=False) + '\n')
            stats['processed_new'] += 1
            newly_written += 1
            if pbar is not None:
                pbar.update(1)
            if newly_written % args.save_every == 0:
                flush_and_sync(fout)
                flush_and_sync(fmeta)
                if not batch_mode_active:
                    save_json_cache(args.cache_json, cache)
        if pbar is not None:
            pbar.close()
        flush_and_sync(fout)
        flush_and_sync(fmeta)
        if not batch_mode_active:
            save_json_cache(args.cache_json, cache)
    final_out = count_nonempty_jsonl_records(args.output_jsonl)
    final_meta = count_nonempty_jsonl_records(meta_out)
    print('=== 7_2 done ===')
    print(f'Output rows:        {final_out:,}')
    print(f'Meta rows:          {final_meta:,}')
    print(f"Newly processed:    {stats['processed_new']:,}")
    print(f"API calls:          {stats['api_calls']:,}")
    print(f"Cache hits:         {stats['cache_hits']:,}")
    print(f"Passthrough (no-op):{stats['passthrough']:,}")
    print(f"Errors:             {stats['errors']:,}")
    print(f'Output path:        {args.output_jsonl}')
    print(f'Meta path:          {meta_out}')
if __name__ == '__main__':
    main()
