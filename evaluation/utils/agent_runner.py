from __future__ import annotations
import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
import jinja2
for _name in ('LiteLLM', 'litellm'):
    logging.getLogger(_name).setLevel(logging.ERROR)
os.environ.setdefault('LITELLM_LOG', 'ERROR')
os.environ.setdefault('MSWEA_COST_TRACKING', 'ignore_errors')
os.environ.setdefault('MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT', '3')
try:
    import litellm
    litellm.suppress_debug_info = True
    litellm.drop_params = True
    from minisweagent.agents.default import DefaultAgent
    from minisweagent.models.litellm_model import LitellmModel
    from minisweagent.environments.local import LocalEnvironment
    from minisweagent.exceptions import InterruptAgentFlow, FormatError
except ImportError as e:
    raise ImportError('pip install mini-swe-agent') from e
_FORBIDDEN_GIT_CMD = re.compile('\\bgit\\s+(log|show|blame|diff|stash|reflog|whatchanged|cherry(?:-pick)?|bisect|format-patch|range-diff|revert|apply)\\b')
_OBS_OUTPUT_MAX_BYTES = int(os.environ.get('VULNLOC_OBS_MAX_BYTES', '4000'))

def _truncate_output(out: str) -> str:
    if not isinstance(out, str) or len(out) <= _OBS_OUTPUT_MAX_BYTES:
        return out
    keep = _OBS_OUTPUT_MAX_BYTES - 80
    return out[:keep].rstrip() + f'\n...[truncated: {len(out) - keep} more bytes; re-run with a narrower query / pipe through `head` to see the rest]'

class VulnLocLocalEnvironment(LocalEnvironment):

    def execute(self, action: dict) -> dict:
        cmd = action.get('command') or '' if isinstance(action, dict) else ''
        if _FORBIDDEN_GIT_CMD.search(cmd):
            return {'returncode': 1, 'output': 'ERROR: git history-inspection commands are disabled in this evaluation (you invoked a blocked subcommand). The repository is at the pre-fix commit; you must locate the vulnerability from source code alone using grep / find / cat. Read-only commands `git grep`, `git ls-files`, `git cat-file` are still allowed.', 'exception_info': 'forbidden_git_command'}
        result = super().execute(action)
        if isinstance(result, dict) and 'output' in result:
            result['output'] = _truncate_output(result['output'])
        return result

class VulnLocLitellmModel(LitellmModel):

    def _parse_actions(self, response) -> list[dict]:
        try:
            return super()._parse_actions(response)
        except FormatError:
            content = response.choices[0].message.content or ''
            if not isinstance(content, str):
                raise
            if _contains_final_json(content):
                return []
            blocks = _BASH_BLOCK_RE.findall(content)
            if blocks:
                return [{'command': blocks[-1].strip()}]
            return [{'command': "echo 'FORMAT_REMINDER: emit exactly one ```bash``` code fence with a shell command, OR a ```json``` block with vulnerable_functions to finalize.'"}]

class VulnLocAgent(DefaultAgent):

    def _has_observation(self) -> bool:
        for m in self.messages:
            if m.get('role') != 'user':
                continue
            c = m.get('content')
            if not isinstance(c, str) or '<returncode>' not in c:
                continue
            if 'FORMAT_REMINDER' in c:
                continue
            return True
        return False

    def _n_schema_rejects(self) -> int:
        return sum((1 for m in self.messages if m.get('role') == 'user' and isinstance(m.get('content'), str) and ('SCHEMA REJECT' in m['content'])))

    def _force_submit_warned(self) -> bool:
        return any((m.get('role') == 'user' and isinstance(m.get('content'), str) and ('STEP LIMIT WARNING' in m['content']) for m in self.messages))
    FORCE_SUBMIT_AT = 5

    def query(self) -> dict:
        sl = int(self.config.step_limit or 0)
        if sl > 0 and sl - self.n_calls <= self.FORCE_SUBMIT_AT and (not self._force_submit_warned()):
            remaining = max(0, sl - self.n_calls)
            self.add_messages({'role': 'user', 'content': f'STEP LIMIT WARNING — you have {remaining} model calls left before this episode is hard-terminated. STOP exploring and submit your CURRENT BEST GUESS now as the final JSON. Even if you are uncertain, emit your single most likely candidate function — an uncertain guess is FAR better than no answer (which scores 0 on every metric). Format:\n```json\n{{"vulnerable_functions": [\n  {{"file": "path/to/file.cc", "function_name": "Class::Method", "reasoning": "<best understanding so far>"}}\n]}}\n```'})
        return super().query()

    def execute_actions(self, message: dict) -> list[dict]:
        content = message.get('content') or ''
        actions = message.get('extra', {}).get('actions', [])
        if isinstance(content, str) and (not actions) and _contains_final_json(content):
            if not self._has_observation():
                return self.add_messages({'role': 'user', 'content': 'PREMATURE SUBMISSION — your answer is rejected. You have not executed any shell commands yet, so you could not have read any source code. Function names guessed from the vulnerability description alone are almost always wrong (the real functions often have unrelated names).\n\nRequired next step: emit exactly ONE ```bash``` fenced command to search the checkout (e.g. `grep -rn "<keyword>" <dir>/ | head -30` or `find <dir> -name "*.cc"`). Read the matching file bodies with `cat` / `sed -n` before submitting the final JSON. Do NOT emit another ```json``` block until you have observed at least one `<returncode>` from a real command.'})
            if not _final_json_well_formed(content) and self._n_schema_rejects() == 0:
                return self.add_messages({'role': 'user', 'content': 'SCHEMA REJECT — your `vulnerable_functions` JSON is malformed. Each entry MUST be an object with BOTH `file` (repo-relative path, e.g. `chrome/browser/foo.cc`) AND `function_name` (qualified C++ name, e.g. `FooBar::DoThing`).\n\nYour entries were either plain strings (`"strcpy"`) or dicts missing one of those keys. Bare library function names (strcpy, memcpy, ...) are never the answer — we want the Chromium function that misuses memory, not the libc primitive.\n\nRe-emit the JSON in exactly this shape:\n```json\n{"vulnerable_functions": [\n  {"file": "path/to/file.cc", "function_name": "Class::Method", "reasoning": "..."}\n]}\n```\nYou have ONE retry. If the next submission is still malformed it will be accepted as-is and score zero.'})
            return self.add_messages({'role': 'exit', 'content': 'FinalAnswerSubmitted', 'extra': {'exit_status': 'FinalAnswerSubmitted', 'submission': content}})
        return super().execute_actions(message)

def _contains_final_json(content: str) -> bool:
    if 'vulnerable_functions' not in content:
        return False
    for block in _JSON_BLOCK_RE.findall(content):
        try:
            obj = json.loads(block)
            if 'vulnerable_functions' in obj:
                return True
        except json.JSONDecodeError:
            continue
    for m in _BARE_JSON_OBJ_RE.findall(content):
        try:
            obj = json.loads(m)
            if 'vulnerable_functions' in obj:
                return True
        except json.JSONDecodeError:
            continue
    return False

def _final_json_well_formed(content: str) -> bool:
    if 'vulnerable_functions' not in content:
        return False
    candidates = list(_JSON_BLOCK_RE.findall(content)) + list(_BARE_JSON_OBJ_RE.findall(content))
    for block in candidates:
        try:
            obj = json.loads(block)
        except json.JSONDecodeError:
            continue
        items = obj.get('vulnerable_functions')
        if not isinstance(items, list):
            continue
        if any((isinstance(x, dict) and (x.get('file') or '') and (x.get('function_name') or x.get('func_name') or x.get('name') or '') for x in items)):
            return True
    return False
DEFAULT_PROMPTS_DIR = Path(__file__).resolve().parent.parent / 'configs' / 'agent_prompts'
TASK_TEMPLATE_FOR_FIELD = {'cve_desc_restated': 'task_cve_desc_restated.txt.j2', 'cve_desc': 'task_cve_desc.txt.j2', 'issue_summary': 'task_issue_summary.txt.j2', 'issue_description': 'task_issue_description.txt.j2'}
ISSUE_DESCRIPTION_TRUNC_CHARS = 12000

def load_system_prompt(prompts_dir: Path=DEFAULT_PROMPTS_DIR, explicit_file: str | None=None) -> str:
    if explicit_file:
        return Path(explicit_file).read_text(encoding='utf-8')
    return (prompts_dir / 'system_prompt.txt').read_text(encoding='utf-8')

def load_task_template(test_field: str, prompts_dir: Path=DEFAULT_PROMPTS_DIR) -> str:
    fname = TASK_TEMPLATE_FOR_FIELD.get(test_field)
    if not fname:
        raise ValueError(f'No task template mapped for test_field={test_field!r}')
    return (prompts_dir / fname).read_text(encoding='utf-8')

def render_task_prompt(template_str: str, record: dict, test_field: str) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    tmpl = env.from_string(template_str)
    if test_field == 'issue_summary':
        summaries = [i.get('summary') for i in record.get('issues') or [] if i.get('summary')]
        return tmpl.render(cve_id=record['cve_id'], issue_summaries=summaries)
    if test_field == 'issue_description':
        descs = []
        for i in record.get('issues') or []:
            d = ((i.get('content') or {}).get('description') or {}).get('content')
            if d and d.strip():
                descs.append(d[:ISSUE_DESCRIPTION_TRUNC_CHARS])
        if not descs:
            summaries = [i.get('summary') for i in record.get('issues') or [] if i.get('summary')]
            descs = summaries
        return tmpl.render(cve_id=record['cve_id'], issue_descriptions=descs)
    if test_field == 'cve_desc':
        return tmpl.render(cve_id=record['cve_id'], cve_desc=record.get('cve_desc', ''))
    if test_field == 'cve_desc_restated':
        return tmpl.render(cve_id=record['cve_id'], cve_desc_restated=record.get('cve_desc_restated', ''))
    raise ValueError(f'Unsupported test_field: {test_field}')
_JSON_BLOCK_RE = re.compile('```(?:json)?\\s*(\\{.*?\\})\\s*```', re.DOTALL)
_BARE_JSON_OBJ_RE = re.compile('\\{[^{}]*"vulnerable_functions"\\s*:\\s*\\[.*?\\]\\s*\\}', re.DOTALL)
_BASH_BLOCK_RE = re.compile('```(?:bash|sh|shell)\\s*\\n(.*?)\\n```', re.DOTALL)

def _find_vuln_funcs_in(text: str) -> list[dict] | None:
    if not isinstance(text, str) or 'vulnerable_functions' not in text:
        return None
    for block in reversed(_JSON_BLOCK_RE.findall(text)):
        try:
            obj = json.loads(block)
            if 'vulnerable_functions' in obj:
                return obj['vulnerable_functions']
        except json.JSONDecodeError:
            continue
    for m in reversed(_BARE_JSON_OBJ_RE.findall(text)):
        try:
            obj = json.loads(m)
            if 'vulnerable_functions' in obj:
                return obj['vulnerable_functions']
        except json.JSONDecodeError:
            continue
    return None

def _fallback_extract_prediction(messages: list[dict]) -> list[dict]:
    import re as _re
    from collections import Counter
    file_counts: Counter = Counter()
    file_re = _re.compile('(?:\\.{0,2}/|\\b)([\\w./_\\-]+\\.(?:cc|cpp|cxx|h|hpp|hxx|c|mm))\\b')
    method_re = _re.compile('\\b([A-Z][\\w]*(?:::[\\w]+)+)\\b')
    method_set: set[str] = set()
    for m in messages:
        role = m.get('role')
        if role == 'assistant':
            for tc in m.get('tool_calls') or []:
                fn = (tc.get('function') or {}).get('arguments') or ''
                if isinstance(fn, str):
                    for f in file_re.findall(fn):
                        file_counts[f.lstrip('./')] += 1
            c = m.get('content') or ''
            if isinstance(c, list):
                c = '\n'.join((b.get('text', '') for b in c if isinstance(b, dict)))
            if isinstance(c, str):
                for f in file_re.findall(c):
                    file_counts[f.lstrip('./')] += 1
                method_set.update(method_re.findall(c))
        elif role == 'tool':
            c = m.get('content') or ''
            if isinstance(c, str):
                for f in file_re.findall(c):
                    file_counts[f.lstrip('./')] += 1
    if not file_counts:
        return []
    best_file = file_counts.most_common(1)[0][0]
    fn_name = next(iter(sorted(method_set, key=lambda s: -len(s))), '') if method_set else ''
    return [{'file': best_file, 'function_name': fn_name or '__heuristic_fallback__', 'reasoning': '[fallback] agent ran out of steps without final JSON; guessed from most-investigated file in trajectory'}]

def parse_agent_predictions(messages: list[dict]) -> list[dict]:
    for msg in reversed(messages):
        if msg.get('role') != 'assistant':
            continue
        result = _find_vuln_funcs_in(msg.get('content') or '')
        if result is not None:
            return result
        for tc in msg.get('tool_calls') or []:
            fn = tc.get('function') or {}
            args_str = fn.get('arguments') or ''
            result = _find_vuln_funcs_in(args_str)
            if result is not None:
                return result
            if isinstance(args_str, str):
                try:
                    outer = json.loads(args_str)
                except json.JSONDecodeError:
                    continue
                for field in ('command', 'cmd', 'script', 'bash'):
                    v = outer.get(field)
                    if isinstance(v, str):
                        result = _find_vuln_funcs_in(v)
                        if result is not None:
                            return result
    return _fallback_extract_prediction(messages)

def normalize_predictions(raw_preds: list[dict]) -> list[dict]:
    out = []
    for p in raw_preds:
        if not isinstance(p, dict):
            continue
        f = p.get('file', '') or ''
        fn = p.get('function_name') or p.get('func_name') or p.get('name') or ''
        if not fn:
            continue
        out.append({'file': f, 'sig': fn})
    return out

class WorktreeManager:

    @staticmethod
    def prewarmed_path(worktree_dir: Path, commit_id: str) -> Path:
        return Path(worktree_dir) / f'wt_{commit_id[:12]}'

    def __init__(self, repo_path: Path, worktree_dir: Path=Path('./worktrees')):
        self.repo_path = Path(repo_path)
        self.worktree_dir = Path(worktree_dir)
        self.worktree_dir.mkdir(parents=True, exist_ok=True)
        self._legacy_path: Path | None = None
        subprocess.run(['git', 'worktree', 'prune'], cwd=self.repo_path, capture_output=True)

    def _run(self, cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        if r.returncode != 0:
            raise subprocess.CalledProcessError(r.returncode, cmd, output=r.stdout, stderr=(r.stderr or '').strip() or '<no stderr>')
        return r

    def _try_prewarmed(self, parent_id: str) -> Path | None:
        pw = self.prewarmed_path(self.worktree_dir, parent_id)
        if not pw.is_dir():
            return None
        r = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=pw, capture_output=True, text=True)
        if r.returncode != 0:
            return None
        if r.stdout.strip() != parent_id:
            return None
        return pw

    def checkout(self, parent_id: str) -> Path:
        pw = self._try_prewarmed(parent_id)
        if pw is not None:
            return pw
        if self._legacy_path is not None and (not self._legacy_path.exists()):
            subprocess.run(['git', 'worktree', 'prune'], cwd=self.repo_path, capture_output=True)
            self._legacy_path = None
        if self._legacy_path is None:
            self._legacy_path = self.worktree_dir / f'chromium_bench_{os.getpid()}'
            if self._legacy_path.exists():
                subprocess.run(['git', 'worktree', 'remove', '--force', str(self._legacy_path)], cwd=self.repo_path, capture_output=True)
            import fcntl
            lock_path = Path(self.repo_path).parent / '.vuln_worktree_add.lock'
            try:
                with open(lock_path, 'w') as _lock_f:
                    fcntl.flock(_lock_f.fileno(), fcntl.LOCK_EX)
                    try:
                        self._run(['git', 'worktree', 'add', str(self._legacy_path), parent_id, '--detach'], cwd=self.repo_path)
                    finally:
                        fcntl.flock(_lock_f.fileno(), fcntl.LOCK_UN)
            except subprocess.CalledProcessError as e:
                e.strerror = f'git worktree add failed: {e.stderr}'
                raise
        else:
            self._run(['git', 'checkout', '--detach', parent_id], cwd=self._legacy_path)
        return self._legacy_path

    def cleanup(self):
        if self._legacy_path and self._legacy_path.exists():
            subprocess.run(['git', 'worktree', 'remove', '--force', str(self._legacy_path)], cwd=self.repo_path, capture_output=True)
            self._legacy_path = None

def run_agent_on_instance(record: dict, commit_id: str, parent_id: str, wt: WorktreeManager, model_name: str, system_prompt: str, task_prompt: str, step_limit: int=30, cost_limit: float=3.0, cmd_timeout: int=30, traj_path: Path | None=None) -> dict:
    t0 = time.time()
    wt_path = wt.checkout(parent_id)
    env = VulnLocLocalEnvironment(cwd=str(wt_path), timeout=cmd_timeout, env={'PAGER': 'cat', 'GIT_PAGER': 'cat'})
    _m = model_name.lower()
    is_openai_proper = _m.startswith(('openai/gpt-', 'openai/o', 'openai/chatgpt', 'openai/text-')) or _m.startswith(('gpt-', 'o1-', 'o3-', 'o4-', 'chatgpt'))
    is_qwen_like = not is_openai_proper
    if is_qwen_like:
        model_kwargs = {'temperature': 0.7, 'top_p': 0.8, 'presence_penalty': 1.5, 'extra_body': {'top_k': 20, 'min_p': 0.0, 'repetition_penalty': 1.0}}
    else:
        model_kwargs = {'temperature': 0.7}
    agent = VulnLocAgent(VulnLocLitellmModel(model_name=model_name, model_kwargs=model_kwargs), env, system_template=system_prompt, instance_template='{{ task }}', step_limit=step_limit, cost_limit=cost_limit)
    error = None
    try:
        agent.run(task=task_prompt)
    except Exception as e:
        error = f'{type(e).__name__}: {e}'
    elapsed_s = round(time.time() - t0, 1)
    if traj_path is not None:
        traj_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            agent.save(traj_path)
        except Exception:
            pass
    raw_preds = parse_agent_predictions(agent.messages)
    predictions = normalize_predictions(raw_preds)
    n_steps = sum((1 for m in agent.messages if m.get('role') == 'assistant'))
    return {'predictions': predictions, 'raw_predictions': raw_preds, 'agent_steps': n_steps, 'agent_cost': round(float(getattr(agent, 'cost', 0.0)), 4), 'elapsed_s': elapsed_s, 'error': error}
