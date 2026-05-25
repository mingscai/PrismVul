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
PROMPT_VERSION = '7_3_v1'
DEFAULT_INPUT = Path('data/processing/chromium_cve_data.jsonl')
DEFAULT_OUTPUT = Path('data/processing/chromium_cve_data.cve_desc_struct.jsonl')
DEFAULT_CACHE = Path('cache/cve_desc_struct_cache.json')
OUTPUT_JSON_SCHEMA = {'type': 'object', 'properties': {'vulnerability_type': {'type': ['string', 'null'], 'description': "Class/category of the flaw, e.g. 'Use-after-free', 'Out-of-bounds read'"}, 'root_cause': {'type': ['string', 'null'], 'description': 'Underlying technical reason the vulnerability exists'}, 'exploitation_method': {'type': ['string', 'null'], 'description': 'How an attacker triggers the vulnerability'}, 'privilege_required': {'type': ['string', 'null'], 'enum': ['Low', 'High', None], 'description': "Access level needed to exploit: 'Low', 'High', or null"}, 'user_interaction_required': {'type': ['boolean', 'null'], 'description': 'true if user action required; false if fully remote; null if unclear'}, 'impact': {'type': 'array', 'items': {'type': 'string'}, 'description': "Exploit consequences, e.g. ['Denial of Service', 'Arbitrary Code Execution']"}, 'affected_software': {'type': 'object', 'properties': {'name': {'type': ['string', 'null'], 'description': 'Product/software name'}, 'version': {'type': ['string', 'null'], 'description': 'Version as stated, or null'}}, 'required': ['name', 'version'], 'additionalProperties': False}, 'affected_location': {'type': 'array', 'items': {'type': 'object', 'properties': {'brief': {'type': ['string', 'null'], 'description': 'Component/subsystem description'}, 'file': {'type': ['string', 'null'], 'description': 'Source file name or path'}, 'function': {'type': ['string', 'null'], 'description': 'Function or method name'}}, 'required': ['brief', 'file', 'function'], 'additionalProperties': False}, 'description': 'Affected code locations; may be []'}, 'attack_example': {'type': ['string', 'null'], 'description': 'Specific attack scenario stated in the description, or null'}}, 'required': ['vulnerability_type', 'root_cause', 'exploitation_method', 'privilege_required', 'user_interaction_required', 'impact', 'affected_software', 'affected_location', 'attack_example'], 'additionalProperties': False}
SYSTEM_PROMPT = 'You are a cybersecurity information extraction assistant. Extract structured information from CVE descriptions.\n\nTASK:\nGiven a CVE description, return a JSON object with the fields listed below.\n\nThis is a conservative span-first extraction task performed in two internal steps:\nStep 1: identify candidate spans explicitly stated in the description.\nStep 2: assign those spans to the output fields.\n\nDo not expose the intermediate steps. Return only the final JSON object.\n\nCORE PRINCIPLES:\n- Extract only information explicitly stated in the description.\n- Prefer the shortest faithful span copied directly from the description whenever possible.\n- Minimal normalization is allowed only when it does not add new facts and does not move away from the original wording more than necessary.\n- Do not infer unstated technical details.\n- Do not use outside knowledge.\n- For span-like fields, preserve original wording and capitalization as much as possible.\n- Each extracted span should be assigned to at most one field.\n- Prefer not to duplicate the same span across multiple fields.\n- If a span could fit multiple fields, assign it to the most specific or primary field only.\n- Leave a field as null (or []) rather than reusing a span already assigned elsewhere, unless the description provides a distinct supporting span.\n\nFIELD DEFINITIONS:\n\nvulnerability_type\n  The span in the description that states the class or category of the flaw.\n  Prefer the shortest faithful text span copied directly from the description.\n  Do not normalize to CWE terminology unless the description already uses that wording.\n  Examples:\n    - "Use-after-free"\n    - "Type Confusion"\n    - "Integer overflow"\n    - "Insufficient policy enforcement"\n    - "incorrect optimization"\n  If not clearly stated, use null.\n\nroot_cause\n  The span in the description that states the underlying technical reason the vulnerability exists.\n  Focus on the mechanism, not the impact.\n  Prefer the shortest faithful text span copied directly from the description.\n  Do not paraphrase or expand beyond the text.\n  Examples:\n    - "does not properly validate input length before copying"\n    - "fails to check array bounds during memory access"\n    - "does not properly handle concurrent access to shared state"\n    - "insufficient bounds checking"\n  If not stated, use null.\n\nexploitation_method\n  The span in the description that states how an attacker triggers the vulnerability.\n  Prefer the shortest faithful text span copied directly from the description.\n  Keep the original wording when possible.\n  Examples:\n    - "via a crafted HTML page"\n    - "via a long string in a malformed packet"\n    - "by opening a specially crafted PDF file"\n    - "via unknown vectors"\n  If not stated, use null.\n\nprivilege_required\n  The access level explicitly required to exploit the vulnerability.\n  Allowed values:\n  - "Low"  — the description explicitly indicates a remote or unauthenticated attacker,\n             or otherwise clearly states no special privileges are needed\n  - "High" — the description explicitly indicates local access, authenticated access,\n             or elevated/administrative privileges are required\n  - null   — not specified or ambiguous\n  Do not infer privilege requirements from general context.\n\nuser_interaction_required\n  Whether the description explicitly indicates that a user must perform an action.\n  - true  — the text explicitly mentions an action such as visiting, opening, clicking,\n            following a link, installing, or similar user behavior\n  - false — the text explicitly indicates exploitation is remote/automatic without user action\n  - null  — not specified or unclear\n  Do not infer user interaction solely from phrases like "via a crafted HTML page".\n\nimpact\n  A list of text spans in the description that state exploit consequences.\n  Prefer short faithful spans copied directly from the description.\n  Do not normalize, upgrade, or reinterpret the wording.\n  Examples:\n    - "cause a denial of service"\n    - "execute arbitrary code"\n    - "memory corruption"\n    - "bypass content security policy"\n  If no impact is stated, use [].\n\naffected_software\n  The software product targeted.\n  - name:    Product or software name as stated in the description\n             (e.g. "Google Chrome", "Adobe Flash Player")\n  - version: Version string exactly as stated in the description\n             (e.g. "before 53.0", "47.x")\n             Use null if the description gives no version information.\n\naffected_location\n  List of specific code or component locations explicitly mentioned.\n  Each item:\n  - brief:    A high-level name explicitly mentioned in the description that identifies\n              the component, module, subsystem, class, or namespace where the vulnerability\n              resides (e.g. "Extensions implementation", "V8", "media loader", "navigation",\n              "Skia", "ANGLE", "ScopedClipboardWriter", "UnicodeString").\n              brief must NOT contain file paths, file names, or function/method names.\n              If the description mentions only a file path with no associated component,\n              class, or namespace name, set brief to null.\n  - file:     Source file name or path if explicitly mentioned, otherwise null\n  - function: Function or method name if explicitly mentioned, otherwise null\n  Use one item per distinct location phrase explicitly mentioned in the text.\n  Do not expand or normalize beyond the description.\n  If no location is mentioned, use [].\n\nattack_example\n  A concrete example attack scenario explicitly described in the CVE, beyond the general trigger phrase.\n  Prefer the shortest faithful text span copied directly from the description.\n  Do not duplicate exploitation_method unless the text clearly provides a distinct example.\n  If no such concrete example is given, use null.\n\nINTERNAL PROCEDURE:\nFollow these steps internally before producing the final JSON:\n1. Identify candidate spans explicitly stated in the description.\n2. Determine which candidate spans correspond to which fields.\n3. Assign each span to at most one field.\n4. Prefer the most specific span for each field.\n5. If no distinct span supports a field, return null or [] for that field.\n6. Return only the final JSON object.\n\nRULES:\n1. Extract only what is explicitly supported by the description. Do not infer or assume.\n2. Whenever possible, extract the shortest faithful span directly from the description rather than converting it into a standardized label.\n3. Minimal normalization is allowed only when it preserves the same fact without adding detail.\n4. For span-like fields, preserve original wording and capitalization as much as possible.\n5. Do not expand abbreviations, component names, or technical terms beyond what the description itself says.\n6. Do not reuse the same span across multiple fields unless the description provides no other explicit evidence and reuse is absolutely necessary. Prefer null instead.\n7. If a field cannot be determined from the text, use null (or [] for list fields).\n8. All fields must be present in the output.\n9. Return valid JSON only. No markdown fences. No extra keys.\n\nEXAMPLES:\n\n[Example 1]\nInput:\nV8 in Google Chrome had an incorrect optimization that could allow a remote attacker to perform arbitrary read/write via a crafted HTML page.\n\nOutput:\n{"vulnerability_type":"incorrect optimization","root_cause":null,"exploitation_method":"via a crafted HTML page","privilege_required":"Low","user_interaction_required":null,"impact":["perform arbitrary read/write"],"affected_software":{"name":"Google Chrome","version":null},"affected_location":[{"brief":"V8","file":null,"function":null}],"attack_example":null}\n\n[Example 2]\nInput:\nType Confusion in V8 in Google Chrome allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.\n\nOutput:\n{"vulnerability_type":"Type Confusion","root_cause":null,"exploitation_method":"via a crafted HTML page","privilege_required":"Low","user_interaction_required":null,"impact":["execute arbitrary code inside a sandbox"],"affected_software":{"name":"Google Chrome","version":null},"affected_location":[{"brief":"V8","file":null,"function":null}],"attack_example":null}\n\n[Example 3]\nInput:\nUse-after-free vulnerability in the media loader in Google Chrome allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors, a different vulnerability than CVE-2013-2846.\n\nOutput:\n{"vulnerability_type":"Use-after-free","root_cause":null,"exploitation_method":"via unknown vectors","privilege_required":"Low","user_interaction_required":null,"impact":["cause a denial of service","unspecified other impact"],"affected_software":{"name":"Google Chrome","version":null},"affected_location":[{"brief":"media loader","file":null,"function":null}],"attack_example":null}\n\n[Example 4]\nInput:\nGoogle Chrome allowed remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via vectors related to large typed arrays.\n\nOutput:\n{"vulnerability_type":null,"root_cause":null,"exploitation_method":"via vectors related to large typed arrays","privilege_required":"Low","user_interaction_required":null,"impact":["cause a denial of service","memory corruption","unspecified other impact"],"affected_software":{"name":"Google Chrome","version":null},"affected_location":[],"attack_example":null}\n\n[Example 5]\nInput:\nInsufficient policy enforcement in navigation in Google Chrome allowed a remote attacker to bypass content security policy via a crafted HTML page.\n\nOutput:\n{"vulnerability_type":"Insufficient policy enforcement","root_cause":null,"exploitation_method":"via a crafted HTML page","privilege_required":"Low","user_interaction_required":null,"impact":["bypass content security policy"],"affected_software":{"name":"Google Chrome","version":null},"affected_location":[{"brief":"navigation","file":null,"function":null}],"attack_example":null}\n\n[Example 6]\nInput:\nA vulnerability in the ScopedClipboardWriter::WritePickledData function in ui/base/clipboard/scoped_clipboard_writer.cc in Google Chrome before 33.0.1750.152 on OS X and Linux and before 33.0.1750.154 on Windows does not verify a certain format value.\n\nOutput:\n{"vulnerability_type":null,"root_cause":"does not verify a certain format value","exploitation_method":null,"privilege_required":null,"user_interaction_required":null,"impact":[],"affected_software":{"name":"Google Chrome","version":"before 33.0.1750.152 on OS X and Linux and before 33.0.1750.154 on Windows"},"affected_location":[{"brief":"ScopedClipboardWriter","file":"ui/base/clipboard/scoped_clipboard_writer.cc","function":"ScopedClipboardWriter::WritePickledData"}],"attack_example":null}\n\n\nReturn JSON only. No markdown. No extra keys.\n'

def build_user_prompt(cve_id: str, cve_desc: str) -> str:
    return f'Extract structured information and return json.\n\nDESCRIPTION_BEGIN\n{cve_desc}\nDESCRIPTION_END'

@dataclass
class CallResult:
    ok: bool
    struct: dict[str, Any] | None
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
        has_struct = isinstance(record.get('cve_desc_struct'), dict)
        row = {'line_no': idx, 'record_key': cve_record_key(record, idx), 'status': 'backfilled_from_output', 'model': model, 'prompt_version': PROMPT_VERSION, 'structured': has_struct, 'cache_hit': None, 'attempts': None, 'elapsed_ms': None, 'usage': None, 'error': None}
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
        cve_desc = str(record.get('cve_desc_restated') or record.get('cve_desc') or '').strip()
        if not cve_desc:
            continue
        cve_id = str(record.get('cve_id') or cve_record_key(record, line_no)).strip()
        seen += 1
        if random.randrange(seen) == 0:
            chosen = (cve_id, cve_desc)
    if chosen is None:
        raise SystemExit(f'No records with cve_desc_restated/cve_desc in: {input_jsonl}')
    cve_id, cve_desc = chosen
    print('=== 7_3 demo prompt ===')
    print(f'Input path:    {input_jsonl}')
    print(f'Sample CVE_ID: {cve_id}')
    print('--- SYSTEM ---')
    print(SYSTEM_PROMPT)
    print('--- USER ---')
    print(build_user_prompt(cve_id, cve_desc))

def build_cache_key(*, model: str, cve_desc: str) -> str:
    h = hashlib.sha256()
    h.update(PROMPT_VERSION.encode('utf-8'))
    h.update(b'\n')
    h.update(model.encode('utf-8'))
    h.update(b'\n')
    h.update(cve_desc.encode('utf-8'))
    return h.hexdigest()

def parse_cve_struct(raw: str) -> dict[str, Any]:
    text = re.sub('^```[a-zA-Z]*\\s*', '', raw.strip())
    text = re.sub('\\s*```$', '', text)
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    raise ValueError(f'Cannot parse struct from: {raw[:200]!r}')

def call_anthropic(*, client: Any, model: str, cve_id: str, cve_desc: str, max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool) -> CallResult:
    last_error: str | None = None
    last_content = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_user_prompt(cve_id, cve_desc)
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
            struct = parse_cve_struct(content)
            return CallResult(ok=True, struct=struct, attempts=attempt, raw_content=content, usage=last_usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_usage = locals().get('last_usage', last_usage)
            if attempt < max_retries:
                time.sleep(retry_initial_sleep * 2 ** (attempt - 1))
    return CallResult(ok=False, struct=None, attempts=max_retries, raw_content=last_content, usage=last_usage, error=last_error)

def call_openai_compatible(*, client: Any, model: str, cve_id: str, cve_desc: str, max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool, is_gpt_model: bool) -> CallResult:
    last_error: str | None = None
    last_content = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_user_prompt(cve_id, cve_desc)
        try:
            tokens_key = 'max_completion_tokens' if is_gpt_model else 'max_tokens'
            create_kwargs: dict[str, Any] = {'model': model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}], tokens_key: max_tokens}
            if use_structured_output:
                if is_gpt_model:
                    create_kwargs['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'cve_desc_struct', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
                else:
                    create_kwargs['response_format'] = {'type': 'json_object'}
            response = client.chat.completions.create(**create_kwargs)
            choice = response.choices[0].message
            content = (getattr(choice, 'content', '') or '').strip()
            ru = getattr(response, 'usage', None)
            last_usage = {'prompt_tokens': getattr(ru, 'prompt_tokens', None), 'completion_tokens': getattr(ru, 'completion_tokens', None), 'total_tokens': getattr(ru, 'total_tokens', None), 'reasoning_tokens': getattr(getattr(ru, 'completion_tokens_details', None), 'reasoning_tokens', None)}
            if not content:
                raise ValueError('empty response')
            struct = parse_cve_struct(content)
            return CallResult(ok=True, struct=struct, attempts=attempt, raw_content=content, usage=last_usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_usage = locals().get('last_usage', last_usage)
            if attempt < max_retries:
                time.sleep(retry_initial_sleep * 2 ** (attempt - 1))
    return CallResult(ok=False, struct=None, attempts=max_retries, raw_content=last_content, usage=last_usage, error=last_error)

def build_openai_batch_item(*, line_no: int, record: dict[str, Any], model: str, cve_id: str, cve_desc: str, max_tokens: int, use_structured_output: bool) -> dict[str, Any]:
    user_prompt = build_user_prompt(cve_id, cve_desc)
    body: dict[str, Any] = {'model': model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}], 'max_completion_tokens': max_tokens}
    if use_structured_output:
        body['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'cve_desc_struct', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
    return {'custom_id': f'{cve_record_key(record, line_no)}::{line_no}', 'method': 'POST', 'url': '/v1/chat/completions', 'body': body}

def build_meta_row(*, line_no: int, record: dict[str, Any], model: str, status: str, call_result: CallResult, cache_hit: bool, elapsed_ms: int) -> dict[str, Any]:
    return {'line_no': line_no, 'record_key': cve_record_key(record, line_no), 'status': status, 'model': model, 'prompt_version': PROMPT_VERSION, 'structured': call_result.ok and call_result.struct is not None, 'cache_hit': cache_hit, 'attempts': call_result.attempts, 'elapsed_ms': elapsed_ms, 'usage': call_result.usage, 'error': call_result.error}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Extract structured NER fields from CVE descriptions using an LLM')
    parser.add_argument('--input-jsonl', type=Path, default=DEFAULT_INPUT)
    parser.add_argument('--output-jsonl', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--meta-out', type=Path, default=None, help='Metadata JSONL path (default: <output>.meta.jsonl)')
    parser.add_argument('--model', type=str, default='claude-sonnet-4-6', help="Model name: 'claude' → Anthropic SDK; 'deepseek'/'gpt' → OpenAI SDK")
    parser.add_argument('--base-url', type=str, default=None, help='API base URL override (DeepSeek default: https://api.deepseek.com/v1)')
    parser.add_argument('--api-key', type=str, default=None, help='API key (fallback: ANTHROPIC_API_KEY / DEEPSEEK_API_KEY / OPENAI_API_KEY)')
    parser.add_argument('--structured-output', action='store_true', help='Use provider structured output / json_schema mode')
    parser.add_argument('--batch-api', action='store_true', help='GPT only: write OpenAI Batch request JSONL to output instead of calling API')
    parser.add_argument('--cache-json', type=Path, default=DEFAULT_CACHE)
    parser.add_argument('--max-tokens', type=int, default=512, help='Max output tokens per LLM call')
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
        print('[7_3] --batch-api ignored (model is not GPT)')
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
        print('[7_3] Recovered output from a partial trailing line')
    if meta_truncated:
        print('[7_3] Recovered meta from a partial trailing line')
    if meta_backfilled:
        print(f'[7_3] Backfilled meta rows from output: {meta_backfilled:,}')
    write_mode = 'a' if resumed_records > 0 else 'w'
    stats = {'processed_new': 0, 'api_calls': 0, 'cache_hits': 0, 'errors': 0}
    with args.output_jsonl.open(write_mode, encoding='utf-8') as fout, meta_out.open(write_mode, encoding='utf-8') as fmeta:
        pbar = None
        if not args.no_progress and tqdm is not None:
            pbar = tqdm(total=pending_total, desc='7_3 struct')
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
            cve_desc = str(record.get('cve_desc_restated') or record.get('cve_desc') or '').strip()
            meta_record = record
            start_ts = time.time()
            status = 'processed'
            cache_hit = False
            if batch_mode_active:
                batch_item = build_openai_batch_item(line_no=input_line_no, record=record, model=args.model, cve_id=cve_id, cve_desc=cve_desc, max_tokens=args.max_tokens, use_structured_output=args.structured_output)
                call_result = CallResult(ok=True, struct=None, attempts=0, raw_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                status = 'batch_prepared'
                write_record = batch_item
            else:
                cache_key = build_cache_key(model=args.model, cve_desc=cve_desc)
                cache_entry = cache.get(cache_key)
                if isinstance(cache_entry, dict) and isinstance(cache_entry.get('struct'), dict):
                    call_result = CallResult(ok=True, struct=cache_entry['struct'], attempts=0, raw_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                    cache_hit = True
                    status = 'cached'
                    stats['cache_hits'] += 1
                else:
                    if is_anthropic:
                        call_result = call_anthropic(client=client, model=args.model, cve_id=cve_id, cve_desc=cve_desc, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output)
                    else:
                        call_result = call_openai_compatible(client=client, model=args.model, cve_id=cve_id, cve_desc=cve_desc, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output, is_gpt_model=is_gpt)
                    stats['api_calls'] += 1
                    if call_result.ok and call_result.struct is not None:
                        cache[cache_key] = {'prompt_version': PROMPT_VERSION, 'model': args.model, 'struct': call_result.struct, 'updated_at': int(time.time())}
                    if args.delay > 0:
                        time.sleep(args.delay)
                if not call_result.ok:
                    stats['errors'] += 1
                    status = 'error'
                    if args.strict_errors:
                        raise RuntimeError(f'LLM failed at line {input_line_no} ({cve_id}): {call_result.error}')
                ordered: dict[str, Any] = {}
                inserted = False
                for k, v in record.items():
                    ordered[k] = v
                    if k == 'cve_desc_restated' and (not inserted):
                        ordered['cve_desc_struct'] = call_result.struct
                        inserted = True
                if not inserted:
                    ordered['cve_desc_struct'] = call_result.struct
                write_record = ordered
            elapsed_ms = int((time.time() - start_ts) * 1000)
            meta_row = build_meta_row(line_no=input_line_no, record=meta_record, model=args.model, status=status, call_result=call_result, cache_hit=cache_hit, elapsed_ms=elapsed_ms)
            fout.write(json.dumps(write_record, ensure_ascii=False) + '\n')
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
    print('=== 7_3 done ===')
    print(f'Output rows:        {final_out:,}')
    print(f'Meta rows:          {final_meta:,}')
    print(f"Newly processed:    {stats['processed_new']:,}")
    print(f"API calls:          {stats['api_calls']:,}")
    print(f"Cache hits:         {stats['cache_hits']:,}")
    print(f"Errors:             {stats['errors']:,}")
    print(f'Output path:        {args.output_jsonl}')
    print(f'Meta path:          {meta_out}')
if __name__ == '__main__':
    main()
