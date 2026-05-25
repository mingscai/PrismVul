#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import os
import random
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
PROMPT_VERSION = '7_1_v6'
DEFAULT_INPUT = Path('data/processing/chromium_cve_data.jsonl')
DEFAULT_OUTPUT = Path('data/processing/chromium_cve_data.cve_desc_masked.jsonl')
DEFAULT_CACHE = Path('cache/cve_desc_masked_cache.json')
ALLOWED_TYPES = {'FUNC', 'FILE', 'SOFTWARE_VERSION', 'OS_VERSION'}
ALLOWED_CONFIDENCE = {'high', 'medium', 'low'}
PLACEHOLDER_PATTERNS = {'FUNC': re.compile('^<FUNC>$'), 'FILE': re.compile('^<FILE>$'), 'SOFTWARE_VERSION': re.compile('^<SOFTWARE_VERSION>$'), 'OS_VERSION': re.compile('^<OS_VERSION>$')}
TYPE_ALIASES = {'function': 'FUNC', 'method': 'FUNC', 'func': 'FUNC', 'filepath': 'FILE', 'path': 'FILE', 'file': 'FILE', 'filename': 'FILE', 'version': 'SOFTWARE_VERSION', 'software_version': 'SOFTWARE_VERSION', 'product_version': 'SOFTWARE_VERSION', 'os': 'OS_VERSION', 'platform': 'OS_VERSION', 'os_version': 'OS_VERSION'}
PLACEHOLDER_RE = re.compile('<(?:FUNC|FILE|SOFTWARE_VERSION|OS_VERSION)>')
TYPE_TO_PLACEHOLDER = {'FUNC': '<FUNC>', 'FILE': '<FILE>', 'SOFTWARE_VERSION': '<SOFTWARE_VERSION>', 'OS_VERSION': '<OS_VERSION>'}
OUTPUT_JSON_SCHEMA = {'type': 'object', 'properties': {'has_leakage': {'type': 'boolean'}, 'sanitized_desc': {'type': ['string', 'null']}, 'replacements': {'type': 'array', 'items': {'type': 'object', 'properties': {'type': {'type': 'string', 'enum': ['FUNC', 'FILE', 'SOFTWARE_VERSION', 'OS_VERSION']}, 'original': {'type': 'string'}}, 'required': ['type', 'original'], 'additionalProperties': False}}}, 'required': ['has_leakage', 'sanitized_desc', 'replacements'], 'additionalProperties': False}
LEAKAGE_PREFILTER_RE = re.compile('(\\b(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\\.(?:c|cc|cpp|cxx|h|hpp|hh|hxx|m|mm|java|js|ts|py|go|rs)\\b|\\b(?:[A-Za-z_~][\\w<>]*::)+[A-Za-z_~][\\w<>]*\\b|\\b[A-Za-z_~][A-Za-z0-9_:<>.~]*\\s+function\\s+in\\b|\\b[A-Za-z0-9_.-]+\\.(?:c|cc|cpp|cxx|h|hpp|hh|hxx|m|mm|java|js|ts|py|go|rs)\\b|\\b\\d+\\.(?:x|\\d+)(?:\\.(?:x|\\d+)){1,4}\\b|\\b(?:Windows|Linux|OS\\s+X|macOS|Mac\\s+OS\\s+X|Mac|Android|iOS|Chrome\\s?OS|ChromeOS)\\b)', re.IGNORECASE)
SYSTEM_PROMPT = 'You are a security-data sanitization assistant.\n\nTASK:\nSanitize a CVE description by removing only explicit implementation-location and environment leakage hints, while preserving the original vulnerability semantics.\n\nThis is a minimal-edit redaction task, not a paraphrasing task.\n\nPRIMARY GOAL:\nReplace only the exact leakage spans that should be hidden.\nKeep all other wording, meaning, and structure unchanged as much as possible.\n\nLEAKAGE TYPES TO REPLACE:\n1) function\n   - Replace concrete function or method symbols with <FUNC>.\n   - Examples:\n     - GetLoadTimes\n     - FrameView::updateLifecyclePhasesInternal\n     - ScopedClipboardWriter::WritePickledData()\n     - UnicodeString::doAppend\n   - If a class/type name appears only as part of a concrete method symbol, replace the whole symbol as <FUNC>.\n     Example:\n     - UnicodeString::doAppend -> <FUNC>\n   - Do not split the class and method into separate placeholders.\n\n2) file\n   - Replace source file paths or standalone source file names with <FILE>.\n   - Examples:\n     - renderer/loadtimes_extension_bindings.cc\n     - ui/base/clipboard/scoped_clipboard_writer.cc\n     - unistr.cpp\n\n3) software_version\n   - Replace explicit software version numbers or version ranges with <SOFTWARE_VERSION>.\n   - Examples:\n     - 47.0.2526.73\n     - 19.x through 22.x\n     - before 53.0.2785.89\n\n4) os_version\n   - Preserve OS/platform family names themselves.\n   - Replace only explicit OS/platform version information with <OS_VERSION>.\n   - Examples of OS/platform family names to preserve:\n     - Windows\n     - Linux\n     - OS X\n     - macOS\n     - Mac\n     - Android\n     - iOS\n     - Chrome OS\n     - ChromeOS\n   - Examples of OS/platform version information to replace:\n     - Windows 10\n     - Windows 11\n     - Android 12\n     - iOS 17.1\n     - macOS 14.4\n     - OS X 10.11\n   - Do not replace a bare OS/platform family name if no explicit version is given.\n   - Keep the OS/platform family name in the text when possible, and replace only the version portion.\n   - Keep the surrounding clause unchanged.\n\nIMPORTANT PRESERVATION RULES:\n- Preserve vulnerability type, product/vendor, impact, attack vector, trigger condition, and exploit semantics.\n- Preserve abstract technical meaning.\n- Preserve module, subsystem, component, and feature names when they provide higher-level semantic context rather than exact implementation location.\n  Examples that are usually preserved:\n  - Compositing\n  - V8\n  - Blink\n  - Autofill\n  - Extensions\n- Preserve isolated class names or type names by default if they are serving as general semantic context rather than a precise implementation-location cue.\n- Do not replace generic technical concepts such as:\n  - permission checks\n  - clipboard handling\n  - renderer process\n  - extension system\n  - sandbox\n- If uncertain whether a term is an abstract semantic identifier or an exact implementation-location identifier, prefer preserving it.\n\nDO NOT OVER-SANITIZE:\n- Do not replace module/component/subsystem names just because they look technical.\n- Do not replace isolated class/type names unless they clearly act as a highly specific implementation-location cue.\n- Do not replace product names or vendor names.\n- Do not replace vulnerability categories or impact phrases.\n\nMINIMAL-EDIT CONSTRAINTS:\n- Preserve every non-leakage part of the description as closely as possible.\n- Do not paraphrase surrounding text.\n- Do not summarize.\n- Do not reorder facts.\n- Do not add, infer, generalize, or remove any vulnerability facts.\n- If the input does not state something, do not add it.\n\nREQUIRED OUTPUT JSON FORMAT (exactly these keys):\n{\n  "has_leakage": true or false,\n  "sanitized_desc": "string" or null,\n  "replacements": [\n    {\n      "type": "FUNC" | "FILE" | "SOFTWARE_VERSION" | "OS_VERSION",\n      "original": "string"\n    }\n  ]\n}\n\nOUTPUT RULES:\n- If has_leakage=false:\n  - sanitized_desc must be null\n  - replacements must be []\n- If has_leakage=true:\n  - sanitized_desc must contain at least one placeholder\n  - replacements must be non-empty\n- Each unique replacement item should appear only once in replacements.\n- List replacements in the order of first appearance in the input text.\n\nDECISION WORKFLOW:\nFollow these steps internally before answering.\nStep 1: Identify exact candidate spans in the original text.\nStep 2: Decide whether each candidate is:\n  - an exact implementation-location/environment leakage cue that should be replaced, or\n  - a higher-level semantic identifier that should be preserved.\nStep 3: Classify only the spans that should be replaced into "FUNC"/"FILE"/"SOFTWARE_VERSION"/"OS_VERSION".\nStep 4: Rewrite the description using only those exact substitutions.\nStep 5: Verify that all non-leakage semantics and wording are preserved.\nStep 6: Return strict JSON only.\n\nEXAMPLES:\n\n[Example 1]\nInput:\nUse-after-free vulnerability in the GetLoadTimes function in renderer/loadtimes_extension_bindings.cc in Google Chrome before 47.0.2526.73 allows remote attackers to cause a denial of service.\nOutput json:\n{"has_leakage":true,"sanitized_desc":"Use-after-free vulnerability in the <FUNC> function in <FILE> in Google Chrome before <SOFTWARE_VERSION> allows remote attackers to cause a denial of service.","replacements":[{"type":"FUNC","original":"GetLoadTimes"},{"type":"FILE","original":"renderer/loadtimes_extension_bindings.cc"},{"type":"SOFTWARE_VERSION","original":"47.0.2526.73"}]}\n\n[Example 2]\nInput:\nThe ScopedClipboardWriter::WritePickledData function in ui/base/clipboard/scoped_clipboard_writer.cc in Google Chrome before 33.0.1750.152 on OS X and Linux and before 33.0.1750.154 on Windows does not verify a certain format value.\nOutput json:\n{"has_leakage":true,"sanitized_desc":"The <FUNC> function in <FILE> in Google Chrome before <SOFTWARE_VERSION> on OS X and Linux and before <SOFTWARE_VERSION> on Windows does not verify a certain format value.","replacements":[{"type":"FUNC","original":"ScopedClipboardWriter::WritePickledData"},{"type":"FILE","original":"ui/base/clipboard/scoped_clipboard_writer.cc"},{"type":"SOFTWARE_VERSION","original":"33.0.1750.152"},{"type":"SOFTWARE_VERSION","original":"33.0.1750.154"}]}\n\n[Example 3]\nInput:\nAn integer overflow exists in the UnicodeString::doAppend() function in unistr.cpp.\nOutput json:\n{"has_leakage":true,"sanitized_desc":"An integer overflow exists in the <FUNC> function in <FILE>.","replacements":[{"type":"FUNC","original":"UnicodeString::doAppend()"},{"type":"FILE","original":"unistr.cpp"}]}\n\n[Example 4]\nInput:\nUse after free in Compositing in Google Chrome prior to 131.0.6778.204 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.\nOutput json:\n{"has_leakage":true,"sanitized_desc":"Use after free in Compositing in Google Chrome prior to <SOFTWARE_VERSION> allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.","replacements":[{"type":"SOFTWARE_VERSION","original":"131.0.6778.204"}]}\n\n[Example 5]\nInput:\nA logic flaw in UnicodeString handling may allow out-of-bounds access.\nOutput json:\n{"has_leakage":false,"sanitized_desc":null,"replacements":[]}\n\n[Example 6]\nInput:\nA use-after-free in the V8 engine may allow remote code execution.\nOutput json:\n{"has_leakage":false,"sanitized_desc":null,"replacements":[]}\n\n[Example 7]\nInput:\nA logic error in permission checks can expose sensitive data.\nOutput json:\n{"has_leakage":false,"sanitized_desc":null,"replacements":[]}\n\n[Example 8]\nInput:\nA vulnerability in Google Chrome on Windows 10 and Android 12 may allow remote attackers to cause a denial of service.\nOutput json:\n{"has_leakage":true,"sanitized_desc":"A vulnerability in Google Chrome on Windows <OS_VERSION> and Android <OS_VERSION> may allow remote attackers to cause a denial of service.","replacements":[{"type":"OS_VERSION","original":"10"},{"type":"OS_VERSION","original":"12"}]}\n\nReturn json only. No markdown. No extra keys.\n'

@dataclass
class CallResult:
    ok: bool
    payload: dict[str, Any]
    attempts: int
    raw_content: str
    reasoning_content: str
    usage: dict[str, int | None]
    error: str | None

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Mask CVE descriptions with Claude/DeepSeek/GPT models')
    parser.add_argument('--input-jsonl', type=Path, default=DEFAULT_INPUT)
    parser.add_argument('--output-jsonl', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--meta-out', type=Path, default=None, help='Optional metadata JSONL path (default: <output>.meta.jsonl)')
    parser.add_argument('--model', type=str, default='claude-sonnet-4-6', help="Model name. If the name contains 'claude' the Anthropic SDK is used; if it contains 'deepseek' or 'gpt' the OpenAI SDK is used.")
    parser.add_argument('--base-url', type=str, default=None, help='Override the API base URL. If not provided, defaults are used (DeepSeek: https://api.deepseek.com/v1; GPT/Claude: provider default).')
    parser.add_argument('--api-key', type=str, default=None, help='API key. If not provided, the key is read from the environment: ANTHROPIC_API_KEY for Claude, DEEPSEEK_API_KEY for DeepSeek, OPENAI_API_KEY for GPT.')
    parser.add_argument('--structured-output', action='store_true', help="Enable structured output. For Anthropic: uses output_config with JSON schema. For DeepSeek/OpenAI-compatible: sets response_format={'type':'json_object'}. For GPT (OpenAI): sets response_format json_schema. Without this flag, the model relies on the JSON format instructions in the prompt.")
    parser.add_argument('--cache-json', type=Path, default=DEFAULT_CACHE, help='Persistent JSON cache for LLM results')
    parser.add_argument('--max-tokens', type=int, default=2048, help='Max output tokens for each model request')
    parser.add_argument('--max-retries', type=int, default=3, help='Max retries per record on API/parse/validation failure')
    parser.add_argument('--retry-initial-sleep', type=float, default=2.0, help='Initial retry sleep seconds (exponential backoff)')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay seconds after each API call')
    parser.add_argument('--save-every', type=int, default=20, help='Flush output/meta/cache every N newly written records')
    parser.add_argument('--max-records', type=int, default=0, help='Process at most N new records (0 means all)')
    parser.add_argument('--prefilter-regex', action='store_true', help='Only call LLM when description matches heuristic leakage regex')
    parser.add_argument('--write-struct-field', action='store_true', help='Also write cve_desc_masked_struct into output records')
    parser.add_argument('--batch-api', action='store_true', help='Only for GPT models: write OpenAI Batch request JSONL to output')
    parser.add_argument('--strict-errors', action='store_true', help='Exit on first unrecoverable LLM error instead of passthrough fallback')
    parser.add_argument('--demo-prompt', action='store_true', help='Print one random system+user prompt example and exit')
    parser.add_argument('--no-progress', action='store_true')
    parser.add_argument('--overwrite', action='store_true')
    return parser.parse_args()

def default_meta_path(output_jsonl: Path) -> Path:
    return output_jsonl.with_suffix(output_jsonl.suffix + '.meta.jsonl')

def load_json_cache(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        with path.open('r', encoding='utf-8') as f:
            payload = json.load(f)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}

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
            next_pos = f.tell()
            stripped = line.strip()
            if not stripped:
                last_good_pos = next_pos
                continue
            try:
                json.loads(stripped.decode('utf-8'))
            except Exception:
                f.truncate(last_good_pos)
                truncated = True
                break
            kept += 1
            last_good_pos = next_pos
    return (kept, truncated)

def ensure_trailing_newline(path: Path) -> None:
    if not path.exists() or not path.is_file():
        return
    with path.open('rb+') as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return
        f.seek(-1, os.SEEK_END)
        if f.read(1) != b'\n':
            f.seek(0, os.SEEK_END)
            f.write(b'\n')

def flush_and_sync(handle) -> None:
    handle.flush()
    os.fsync(handle.fileno())

def truncate_jsonl_to_record_count(path: Path, keep_count: int) -> None:
    if not path.exists() or not path.is_file():
        return
    if keep_count < 0:
        keep_count = 0
    kept = 0
    last_good_pos = 0
    with path.open('rb+') as f:
        while kept < keep_count:
            line = f.readline()
            if not line:
                break
            next_pos = f.tell()
            stripped = line.strip()
            if not stripped:
                last_good_pos = next_pos
                continue
            json.loads(stripped.decode('utf-8'))
            kept += 1
            last_good_pos = next_pos
        f.truncate(last_good_pos)

def count_nonempty_jsonl_records(path: Path) -> int:
    if not path.exists() or not path.is_file():
        return 0
    count = 0
    with path.open('r', encoding='utf-8') as f:
        for raw in f:
            if raw.strip():
                count += 1
    return count

def iter_nonempty_jsonl(path: Path):
    with path.open('r', encoding='utf-8') as f:
        for raw in f:
            if raw.strip():
                yield raw

def cve_record_key(record: dict[str, Any], line_no: int) -> str:
    for key in ('cve_id', 'cve', 'id'):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return f'line:{line_no}'

def build_backfill_meta_row(record: dict[str, Any], line_no: int, model: str) -> dict[str, Any]:
    desc = str(record.get('cve_desc') or '')
    scrubbed = str(record.get('cve_desc_masked') or desc)
    return {'line_no': line_no, 'record_key': cve_record_key(record, line_no), 'status': 'backfilled_from_output', 'model': model, 'prompt_version': PROMPT_VERSION, 'has_leakage': scrubbed != desc, 'replacement_count': None, 'confidence': None, 'cache_hit': None, 'attempts': None, 'elapsed_ms': None, 'usage': None, 'reasoning_chars': None, 'error': None}

def backfill_meta_from_output(output_jsonl: Path, meta_handle, *, start_record: int, model: str) -> int:
    written = 0
    for idx, raw in enumerate(iter_nonempty_jsonl(output_jsonl), start=1):
        if idx < start_record:
            continue
        record = json.loads(raw)
        if not isinstance(record, dict):
            continue
        row = build_backfill_meta_row(record, idx, model)
        meta_handle.write(json.dumps(row, ensure_ascii=False) + '\n')
        written += 1
    return written

def build_user_prompt(cve_id: str, cve_desc: str, previous_error: str | None=None) -> str:
    lines = ['Sanitize the CVE description and return json.', '', f'CVE_ID: {cve_id}', '', 'DESCRIPTION_BEGIN', cve_desc, 'DESCRIPTION_END']
    if previous_error:
        lines.extend(['', 'Your previous response was invalid.', f'Validation error: {previous_error}', 'Please fix and return json only.'])
    return '\n'.join(lines)

def pick_random_prompt_record(input_jsonl: Path) -> tuple[str, str]:
    chosen: tuple[str, str] | None = None
    seen = 0
    for line_no, raw in enumerate(iter_nonempty_jsonl(input_jsonl), start=1):
        try:
            record = json.loads(raw)
        except Exception:
            continue
        if not isinstance(record, dict):
            continue
        cve_desc = str(record.get('cve_desc') or '').strip()
        if not cve_desc:
            continue
        cve_id = str(record.get('cve_id') or cve_record_key(record, line_no)).strip()
        seen += 1
        if random.randrange(seen) == 0:
            chosen = (cve_id, cve_desc)
    if chosen is None:
        raise SystemExit(f'No records with non-empty cve_desc in input: {input_jsonl}')
    return chosen

def print_demo_prompt(input_jsonl: Path) -> None:
    cve_id, cve_desc = pick_random_prompt_record(input_jsonl)
    user_prompt = build_user_prompt(cve_id, cve_desc)
    print('=== 7_1 demo prompt ===')
    print(f'Input path: {input_jsonl}')
    print(f'Sample CVE_ID: {cve_id}')
    print('--- SYSTEM ---')
    print(SYSTEM_PROMPT)
    print('--- USER ---')
    print(user_prompt)

def normalize_response_text(content: Any) -> str:
    if content is None:
        return ''
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get('text') or item.get('content')
                if isinstance(text, str):
                    chunks.append(text)
            elif isinstance(item, str):
                chunks.append(item)
        return '\n'.join(chunks).strip()
    return str(content).strip()

def parse_json_object_from_text(text: str) -> dict[str, Any]:
    s = text.strip()
    if s.startswith('```'):
        s = s.strip('`')
        if s.startswith('json'):
            s = s[4:].strip()
    parsed = json.loads(s)
    if not isinstance(parsed, dict):
        raise ValueError('response is not a JSON object')
    return parsed

def infer_type_from_placeholder(placeholder: str) -> str | None:
    if PLACEHOLDER_PATTERNS['function'].fullmatch(placeholder):
        return 'function'
    if PLACEHOLDER_PATTERNS['file'].fullmatch(placeholder):
        return 'file'
    if PLACEHOLDER_PATTERNS['software_version'].fullmatch(placeholder):
        return 'software_version'
    if PLACEHOLDER_PATTERNS['os_version'].fullmatch(placeholder):
        return 'os_version'
    return None

def normalize_replacement_item(item: dict[str, Any]) -> dict[str, str]:
    raw_type = str(item.get('type') or '').strip().lower()
    raw_original = str(item.get('original') or '').strip()
    if not raw_original:
        raise ValueError('replacement.original must be non-empty')
    normalized_type = TYPE_ALIASES.get(raw_type)
    if normalized_type is None:
        raise ValueError(f'unknown replacement type: {raw_type!r}')
    return {'type': normalized_type, 'original': raw_original}

def validate_and_normalize_payload(payload: dict[str, Any], *, original_desc: str) -> dict[str, Any]:
    required_keys = {'has_leakage', 'sanitized_desc', 'replacements'}
    missing = sorted(required_keys - set(payload.keys()))
    if missing:
        raise ValueError(f'missing keys: {missing}')
    has_leakage = payload.get('has_leakage')
    if not isinstance(has_leakage, bool):
        raise ValueError('has_leakage must be boolean')
    sanitized_desc = payload.get('sanitized_desc')
    if has_leakage:
        if not isinstance(sanitized_desc, str):
            raise ValueError('sanitized_desc must be a string when has_leakage=true')
        sanitized_desc = sanitized_desc.strip()
        if not sanitized_desc:
            raise ValueError('sanitized_desc must be non-empty when has_leakage=true')
    replacements_raw = payload.get('replacements')
    if not isinstance(replacements_raw, list):
        raise ValueError('replacements must be a list')
    normalized_replacements: list[dict[str, str]] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in replacements_raw:
        if not isinstance(item, dict):
            raise ValueError('each replacement must be an object')
        norm = normalize_replacement_item(item)
        key = (norm['type'], norm['original'])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        normalized_replacements.append(norm)
    if has_leakage:
        normalized_replacements = [r for r in normalized_replacements if TYPE_TO_PLACEHOLDER.get(r['type'], '') in sanitized_desc]
        if not PLACEHOLDER_RE.search(sanitized_desc):
            raise ValueError('has_leakage=true but sanitized_desc has no placeholders')
        if not normalized_replacements:
            raise ValueError('has_leakage=true but replacements is empty after validation')
        return {'has_leakage': True, 'sanitized_desc': sanitized_desc, 'replacements': normalized_replacements}
    else:
        return {'has_leakage': False, 'sanitized_desc': original_desc, 'replacements': []}

def extract_usage_dict(response: Any) -> dict[str, int | None]:
    usage = getattr(response, 'usage', None)
    if usage is None:
        return {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    completion_details = getattr(usage, 'completion_tokens_details', None)
    reasoning_tokens = None
    if completion_details is not None:
        reasoning_tokens = getattr(completion_details, 'reasoning_tokens', None)
    return {'prompt_tokens': getattr(usage, 'prompt_tokens', None), 'completion_tokens': getattr(usage, 'completion_tokens', None), 'total_tokens': getattr(usage, 'total_tokens', None), 'reasoning_tokens': reasoning_tokens}

def call_anthropic(*, client: Any, model: str, cve_id: str, cve_desc: str, max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool) -> CallResult:
    fallback_payload = {'has_leakage': False, 'sanitized_desc': cve_desc, 'replacements': []}
    if max_retries < 1:
        max_retries = 1
    last_error: str | None = None
    last_content = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_user_prompt(cve_id, cve_desc, previous_error=last_error)
        try:
            create_kwargs: dict[str, Any] = dict(model=model, max_tokens=max_tokens, system=SYSTEM_PROMPT, messages=[{'role': 'user', 'content': user_prompt}])
            if use_structured_output:
                create_kwargs['output_config'] = {'format': {'type': 'json_schema', 'schema': OUTPUT_JSON_SCHEMA}}
            with client.messages.stream(**create_kwargs) as stream:
                response = stream.get_final_message()
            content = ''
            reasoning = ''
            for block in response.content:
                btype = getattr(block, 'type', None)
                if btype == 'text':
                    content = normalize_response_text(getattr(block, 'text', ''))
                elif btype == 'thinking':
                    reasoning = normalize_response_text(getattr(block, 'thinking', ''))
            ru = getattr(response, 'usage', None)
            usage = {'prompt_tokens': getattr(ru, 'input_tokens', None), 'completion_tokens': getattr(ru, 'output_tokens', None), 'total_tokens': (getattr(ru, 'input_tokens', 0) or 0) + (getattr(ru, 'output_tokens', 0) or 0) if ru else None, 'reasoning_tokens': None}
            if not content:
                raise ValueError('empty response content')
            parsed = parse_json_object_from_text(content)
            normalized = validate_and_normalize_payload(parsed, original_desc=cve_desc)
            return CallResult(ok=True, payload=normalized, attempts=attempt, raw_content=content, reasoning_content=reasoning, usage=usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_usage = locals().get('usage', last_usage)
            if attempt < max_retries:
                sleep_s = retry_initial_sleep * 2 ** (attempt - 1)
                if sleep_s > 0:
                    time.sleep(sleep_s)
    return CallResult(ok=False, payload=fallback_payload, attempts=max_retries, raw_content=last_content, reasoning_content='', usage=last_usage, error=last_error)

def call_openai_compatible(*, client: Any, model: str, cve_id: str, cve_desc: str, max_tokens: int, max_retries: int, retry_initial_sleep: float, use_structured_output: bool, is_gpt_model: bool) -> CallResult:
    fallback_payload = {'has_leakage': False, 'sanitized_desc': cve_desc, 'replacements': []}
    if max_retries < 1:
        max_retries = 1
    last_error: str | None = None
    last_content = ''
    last_reasoning = ''
    last_usage = {'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}
    for attempt in range(1, max_retries + 1):
        user_prompt = build_user_prompt(cve_id, cve_desc, previous_error=last_error)
        try:
            tokens_key = 'max_completion_tokens' if is_gpt_model else 'max_tokens'
            create_kwargs: dict[str, Any] = dict(model=model, messages=[{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}])
            create_kwargs[tokens_key] = max_tokens
            if use_structured_output:
                if is_gpt_model:
                    create_kwargs['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'cve_desc_masked', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
                else:
                    create_kwargs['response_format'] = {'type': 'json_object'}
            response = client.chat.completions.create(**create_kwargs)
            choice = response.choices[0].message
            content = normalize_response_text(getattr(choice, 'content', ''))
            reasoning = normalize_response_text(getattr(choice, 'reasoning_content', ''))
            usage = extract_usage_dict(response)
            if not content:
                raise ValueError('empty response content')
            parsed = parse_json_object_from_text(content)
            normalized = validate_and_normalize_payload(parsed, original_desc=cve_desc)
            return CallResult(ok=True, payload=normalized, attempts=attempt, raw_content=content, reasoning_content=reasoning, usage=usage, error=None)
        except Exception as exc:
            last_error = str(exc)
            last_content = locals().get('content', '')
            last_reasoning = locals().get('reasoning', '')
            last_usage = locals().get('usage', last_usage)
            if attempt < max_retries:
                sleep_s = retry_initial_sleep * 2 ** (attempt - 1)
                if sleep_s > 0:
                    time.sleep(sleep_s)
    return CallResult(ok=False, payload=fallback_payload, attempts=max_retries, raw_content=last_content, reasoning_content=last_reasoning, usage=last_usage, error=last_error)

def build_cache_key(*, model: str, cve_desc: str) -> str:
    h = hashlib.sha256()
    h.update(PROMPT_VERSION.encode('utf-8'))
    h.update(b'\n')
    h.update(model.encode('utf-8'))
    h.update(b'\n')
    h.update(cve_desc.encode('utf-8'))
    return h.hexdigest()

def build_openai_batch_item(*, line_no: int, record: dict[str, Any], model: str, cve_id: str, cve_desc: str, max_tokens: int, use_structured_output: bool) -> dict[str, Any]:
    user_prompt = build_user_prompt(cve_id, cve_desc, previous_error=None)
    body: dict[str, Any] = {'model': model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user_prompt}], 'max_completion_tokens': max_tokens}
    if use_structured_output:
        body['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'cve_desc_masked', 'strict': True, 'schema': OUTPUT_JSON_SCHEMA}}
    return {'custom_id': f'{cve_record_key(record, line_no)}::{line_no}', 'method': 'POST', 'url': '/v1/chat/completions', 'body': body}

def build_meta_row(*, line_no: int, record: dict[str, Any], model: str, status: str, call_result: CallResult, cache_hit: bool, elapsed_ms: int) -> dict[str, Any]:
    payload = call_result.payload
    return {'line_no': line_no, 'record_key': cve_record_key(record, line_no), 'status': status, 'model': model, 'prompt_version': PROMPT_VERSION, 'has_leakage': payload.get('has_leakage'), 'replacement_count': len(payload.get('replacements') or []), 'confidence': payload.get('confidence'), 'cache_hit': cache_hit, 'attempts': call_result.attempts, 'elapsed_ms': elapsed_ms, 'usage': call_result.usage, 'reasoning_chars': len(call_result.reasoning_content or ''), 'error': call_result.error}

def main() -> None:
    args = parse_args()
    if not args.input_jsonl.exists() or not args.input_jsonl.is_file():
        raise SystemExit(f'Input JSONL not found: {args.input_jsonl}')
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
        raise SystemExit(f"Cannot detect provider from model name '{args.model}'. Model name must contain 'claude', 'deepseek', or 'gpt'.")
    if not args.base_url and is_deepseek:
        args.base_url = 'https://api.deepseek.com/v1'
    batch_mode_active = bool(args.batch_api and is_gpt)
    if args.batch_api and (not is_gpt):
        print('[7_1] --batch-api is ignored because model is not GPT')
    client: Any = None
    if not batch_mode_active:
        if args.api_key:
            api_key = args.api_key
        else:
            if is_anthropic:
                env_var = 'ANTHROPIC_API_KEY'
            elif is_deepseek:
                env_var = 'DEEPSEEK_API_KEY'
            else:
                env_var = 'OPENAI_API_KEY'
            api_key = os.environ.get(env_var)
            if not api_key:
                raise EnvironmentError(f'API key not found. Provide --api-key or set the {env_var} environment variable.')
        if is_anthropic:
            if anthropic_sdk is None:
                raise EnvironmentError("Python package 'anthropic' is required for Anthropic API mode. Install it with: pip install anthropic")
            client = anthropic_sdk.Anthropic(api_key=api_key, **{'base_url': args.base_url} if args.base_url else {})
        else:
            if OpenAI is None:
                raise EnvironmentError("Python package 'openai' is required for OpenAI-compatible API mode. Install it with: pip install openai")
            client_kwargs: dict[str, Any] = {'api_key': api_key}
            if args.base_url:
                client_kwargs['base_url'] = args.base_url
            client = OpenAI(**client_kwargs)
    meta_out = args.meta_out or default_meta_path(args.output_jsonl)
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    meta_out.parent.mkdir(parents=True, exist_ok=True)
    total_records = count_nonempty_jsonl_records(args.input_jsonl)
    if total_records <= 0:
        raise SystemExit(f'No non-empty records in input: {args.input_jsonl}')
    if args.overwrite:
        args.output_jsonl.unlink(missing_ok=True)
        meta_out.unlink(missing_ok=True)
        args.output_jsonl.with_suffix(args.output_jsonl.suffix + '.tmp').unlink(missing_ok=True)
        meta_out.with_suffix(meta_out.suffix + '.tmp').unlink(missing_ok=True)
    output_records = 0
    meta_records = 0
    output_truncated = False
    meta_truncated = False
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
        with meta_out.open('a', encoding='utf-8') as fmeta_backfill:
            meta_backfilled = backfill_meta_from_output(args.output_jsonl, fmeta_backfill, start_record=meta_records + 1, model=args.model)
            flush_and_sync(fmeta_backfill)
        meta_records += meta_backfilled
    resumed_records = output_records
    if resumed_records > total_records:
        raise SystemExit(f'Output has more rows than input. Use --overwrite if input changed. output={resumed_records}, input={total_records}')
    cache = {} if batch_mode_active else load_json_cache(args.cache_json)
    pending_total = total_records - resumed_records
    if args.max_records > 0:
        pending_total = min(pending_total, args.max_records)
    print(f'Input records: {total_records:,}')
    print(f'Output path: {args.output_jsonl}')
    print(f'Meta path: {meta_out}')
    print(f"Cache path: {args.cache_json}{(' (unused in batch mode)' if batch_mode_active else '')}")
    print(f'Model: {args.model}')
    print(f"Mode: {('gpt_batch_prepare' if batch_mode_active else 'online_inference')}")
    print(f'Prompt version: {PROMPT_VERSION}')
    print(f'Resume records: {resumed_records:,}')
    print(f'Pending records: {pending_total:,}')
    if output_truncated:
        print('[7_1] Recovered output from a partial trailing line')
    if meta_truncated:
        print('[7_1] Recovered meta from a partial trailing line')
    if meta_backfilled:
        print(f'[7_1] Backfilled meta rows from output: {meta_backfilled:,}')
    write_mode = 'a' if resumed_records > 0 else 'w'
    stats = {'processed_new': 0, 'api_calls': 0, 'cache_hits': 0, 'prefilter_passthrough': 0, 'empty_desc_passthrough': 0, 'errors': 0, 'has_leakage_true': 0}
    with args.output_jsonl.open(write_mode, encoding='utf-8') as fout, meta_out.open(write_mode, encoding='utf-8') as fmeta:
        pbar = None
        if not args.no_progress and tqdm is not None:
            pbar = tqdm(total=pending_total, desc='7_1 scrub')
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
            cve_desc = str(record.get('cve_desc') or '')
            meta_record = record
            start_ts = time.time()
            status = 'processed'
            cache_hit = False
            if batch_mode_active:
                record = build_openai_batch_item(line_no=input_line_no, record=record, model=args.model, cve_id=cve_id, cve_desc=cve_desc, max_tokens=args.max_tokens, use_structured_output=args.structured_output)
                call_result = CallResult(ok=True, payload={'has_leakage': False, 'sanitized_desc': cve_desc, 'replacements': []}, attempts=0, raw_content='', reasoning_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                status = 'batch_prepared'
            elif not cve_desc.strip():
                call_result = CallResult(ok=True, payload={'has_leakage': False, 'sanitized_desc': cve_desc, 'replacements': []}, attempts=0, raw_content='', reasoning_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                status = 'empty_desc_passthrough'
                stats['empty_desc_passthrough'] += 1
            elif args.prefilter_regex and (not LEAKAGE_PREFILTER_RE.search(cve_desc)):
                call_result = CallResult(ok=True, payload={'has_leakage': False, 'sanitized_desc': cve_desc, 'replacements': []}, attempts=0, raw_content='', reasoning_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                status = 'prefilter_passthrough'
                stats['prefilter_passthrough'] += 1
            else:
                cache_key = build_cache_key(model=args.model, cve_desc=cve_desc)
                cache_entry = cache.get(cache_key)
                if isinstance(cache_entry, dict) and isinstance(cache_entry.get('payload'), dict):
                    try:
                        normalized_payload = validate_and_normalize_payload(cache_entry['payload'], original_desc=cve_desc)
                        call_result = CallResult(ok=True, payload=normalized_payload, attempts=0, raw_content='', reasoning_content='', usage={'prompt_tokens': None, 'completion_tokens': None, 'total_tokens': None, 'reasoning_tokens': None}, error=None)
                        cache_hit = True
                        status = 'cached'
                        stats['cache_hits'] += 1
                    except Exception:
                        cache_entry = None
                if not cache_hit:
                    if is_anthropic:
                        call_result = call_anthropic(client=client, model=args.model, cve_id=cve_id, cve_desc=cve_desc, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output)
                    else:
                        call_result = call_openai_compatible(client=client, model=args.model, cve_id=cve_id, cve_desc=cve_desc, max_tokens=args.max_tokens, max_retries=args.max_retries, retry_initial_sleep=args.retry_initial_sleep, use_structured_output=args.structured_output, is_gpt_model=is_gpt)
                    stats['api_calls'] += 1
                    cache[cache_key] = {'prompt_version': PROMPT_VERSION, 'model': args.model, 'payload': call_result.payload, 'updated_at': int(time.time())}
                    if args.delay > 0:
                        time.sleep(args.delay)
            if not call_result.ok:
                stats['errors'] += 1
                status = 'error_passthrough'
                if args.strict_errors:
                    raise RuntimeError(f'LLM failed at line {input_line_no} ({cve_id}): {call_result.error}')
            payload = call_result.payload
            if payload.get('has_leakage'):
                stats['has_leakage_true'] += 1
            if not batch_mode_active:
                scrubbed_fields: dict[str, Any] = {'cve_desc_masked': str(payload.get('sanitized_desc') or cve_desc)}
                if args.write_struct_field:
                    scrubbed_fields['cve_desc_masked_struct'] = {'has_leakage': payload.get('has_leakage'), 'replacements': payload.get('replacements') or []}
                ordered: dict[str, Any] = {}
                for k, v in record.items():
                    ordered[k] = v
                    if k == 'cve_desc':
                        ordered.update(scrubbed_fields)
                for k, v in scrubbed_fields.items():
                    if k not in ordered:
                        ordered[k] = v
                record = ordered
            elapsed_ms = int((time.time() - start_ts) * 1000)
            meta_row = build_meta_row(line_no=input_line_no, record=meta_record, model=args.model, status=status, call_result=call_result, cache_hit=cache_hit, elapsed_ms=elapsed_ms)
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
    final_output_count = count_nonempty_jsonl_records(args.output_jsonl)
    final_meta_count = count_nonempty_jsonl_records(meta_out)
    print('=== 7_1 done ===')
    print(f'Output rows: {final_output_count:,}')
    print(f'Meta rows: {final_meta_count:,}')
    print(f"Newly processed rows: {stats['processed_new']:,}")
    print(f"API calls: {stats['api_calls']:,}")
    print(f"Cache hits: {stats['cache_hits']:,}")
    print(f"Leakage detected rows: {stats['has_leakage_true']:,}")
    print(f"Regex prefilter passthrough: {stats['prefilter_passthrough']:,}")
    print(f"Empty-desc passthrough: {stats['empty_desc_passthrough']:,}")
    print(f"Error passthrough rows: {stats['errors']:,}")
    print(f'Output path: {args.output_jsonl}')
    print(f'Meta path: {meta_out}')
    print(f"Cache path: {args.cache_json}{(' (unused in batch mode)' if batch_mode_active else '')}")
if __name__ == '__main__':
    main()
