#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any
from tqdm import tqdm
_RE_URL = re.compile('https?://[^\\s]+', re.IGNORECASE)
_RE_CHROMIUM_GIT = re.compile('https?://chromium\\.googlesource\\.com/.*?chromium/src.*?/\\+/([0-9a-f]{40})', re.IGNORECASE)
_RE_SVN = re.compile('http://src\\.chromium\\.org/viewvc/([^\\s?]+)\\?[^\\s]*view=rev[^\\s]*&[^\\s]*rev[^\\s]*=(\\d+)', re.IGNORECASE)
_RE_CHERRY_PICK_SOURCE = re.compile('\\(cherry picked from commit ([0-9a-f]{7,40})\\)', re.IGNORECASE)
_RE_PROJECT_CHROMIUM = re.compile('Project:\\s*chromium/src\\s*\\n', re.IGNORECASE)
_RE_COMMIT_HASH = re.compile('\\ncommit\\s+([0-9a-f]{40})\\n', re.IGNORECASE)
_RE_LINK_URL = re.compile('Link:\\s*(https?://[^\\s\\n]+)', re.IGNORECASE)
_RE_CHROMIUM_GIT_SIMPLE = re.compile('https?://chromium\\.googlesource\\.com/.*?chromium/src.*?/\\+/([0-9a-f]{40})', re.IGNORECASE)
_SVN_TO_GIT_CACHE: dict[str, list[str]] = {}
_CACHE_FILE: Path | None = None
_SVN_COMMIT_MAP: dict[str, str] | None = None

def load_svn_cache(cache_file: Path) -> dict[str, list[str]]:
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_svn_cache(cache_file: Path, cache: dict[str, list[str]]):
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f'警告：无法保存缓存文件: {e}')

def build_svn_commit_map(src_repo: Path, cache_dir: Path) -> dict[str, str]:
    map_file = cache_dir / 'all_svn_commits.txt'
    if not map_file.exists():
        print('正在生成 SVN commit 映射文件（首次运行，可能需要几分钟）...')
        map_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(['git', 'log', '--format=%H%x09%B', '--grep=git-svn-id:', '--all'], cwd=src_repo, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                with open(map_file, 'w') as f:
                    f.write(result.stdout)
                print(f'SVN commit 映射文件已生成: {map_file}')
            else:
                print(f'警告：生成 SVN commit 映射失败')
                return {}
        except Exception as e:
            print(f'警告：生成 SVN commit 映射时出错: {e}')
            return {}
    print(f'正在加载 SVN commit 映射文件: {map_file}')
    svn_map = {}
    try:
        with open(map_file, 'r') as f:
            current_hash = None
            current_msg = []
            for line in f:
                if '\t' in line and len(line.split('\t')[0]) == 40:
                    if current_hash and current_msg:
                        msg = '\n'.join(current_msg)
                        for msg_line in current_msg:
                            if 'git-svn-id:' in msg_line:
                                match = re.search('git-svn-id:\\s+(svn://[^\\s]+)', msg_line)
                                if match:
                                    svn_url = match.group(1).split()[0]
                                    svn_map[svn_url] = current_hash
                                break
                    parts = line.split('\t', 1)
                    current_hash = parts[0]
                    current_msg = [parts[1].rstrip()] if len(parts) > 1 else []
                elif current_hash:
                    current_msg.append(line.rstrip())
            if current_hash and current_msg:
                for msg_line in current_msg:
                    if 'git-svn-id:' in msg_line:
                        match = re.search('git-svn-id:\\s+(svn://[^\\s]+)', msg_line)
                        if match:
                            svn_url = match.group(1).split()[0]
                            svn_map[svn_url] = current_hash
                        break
        print(f'加载了 {len(svn_map):,} 个 SVN 到 Git 的映射')
        return svn_map
    except Exception as e:
        print(f'警告：解析 SVN commit 映射时出错: {e}')
        return {}

def svn_revision_to_git_hashes(svn_path: str, revision: str, src_repo: Path) -> list[str]:
    cache_key = f'{svn_path}@{revision}'
    if cache_key in _SVN_TO_GIT_CACHE:
        return _SVN_TO_GIT_CACHE[cache_key]
    found_hashes = []
    if _SVN_COMMIT_MAP:
        search_prefix = f'svn://svn.chromium.org/{svn_path}/'
        search_suffix = f'@{revision}'
        for svn_url, git_hash in _SVN_COMMIT_MAP.items():
            if svn_url.startswith(search_prefix) and svn_url.endswith(search_suffix):
                found_hashes.append(git_hash)
    unique_hashes = list(dict.fromkeys(found_hashes))
    _SVN_TO_GIT_CACHE[cache_key] = unique_hashes
    return unique_hashes
_REVIEW_TO_HASH_CACHE: dict[str, str | None] = {}
_REVIEW_CACHE_FILE: Path | None = None

def load_review_cache(cache_file: Path) -> dict[str, str | None]:
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_review_cache(cache_file: Path, cache: dict[str, str | None]):
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f'警告：无法保存 review 缓存文件: {e}')

def extract_change_number_from_review_url(url: str) -> str | None:
    patterns = ['chromium-review\\.googlesource\\.com/#/c/(\\d+)(?:[/?#]|$)', 'chromium-review\\.googlesource\\.com/c/(\\d+)(?:[/?#]|$)', 'chromium-review\\.googlesource\\.com/c/[^/]+/[^/]+/\\+/(\\d+)', 'chromium-review\\.googlesource\\.com/(\\d+)(?:[/?#]|$)']
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

def fetch_commit_hash_from_review(url: str) -> str | None:
    if url in _REVIEW_TO_HASH_CACHE:
        return _REVIEW_TO_HASH_CACHE[url]
    change_number = extract_change_number_from_review_url(url)
    if not change_number:
        _REVIEW_TO_HASH_CACHE[url] = None
        return None
    api_url = f'https://chromium-review.googlesource.com/changes/{change_number}/detail?o=CURRENT_REVISION'
    try:
        req = urllib.request.Request(api_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8')
            if content.startswith(")]}'"):
                content = content[4:]
            data = json.loads(content)
            commit_hash = data.get('current_revision')
            if commit_hash and len(commit_hash) == 40:
                _REVIEW_TO_HASH_CACHE[url] = commit_hash
                return commit_hash
            revisions = data.get('revisions')
            if isinstance(revisions, dict):
                for revision in revisions:
                    if len(revision) == 40:
                        _REVIEW_TO_HASH_CACHE[url] = revision
                        return revision
    except Exception as e:
        pass
    _REVIEW_TO_HASH_CACHE[url] = None
    return None

def resolve_review_links(records: list[dict[str, Any]], batch_size: int=50, delay: float=1.0) -> list[dict[str, Any]]:
    review_urls_to_fetch = set()
    for record in records:
        for commit in record.get('src_commit_links', []):
            if commit.get('tag') == 'review' and commit.get('url') and (not commit.get('hash')):
                url = commit['url']
                if url not in _REVIEW_TO_HASH_CACHE:
                    review_urls_to_fetch.add(url)
    review_urls_to_fetch = sorted(review_urls_to_fetch)
    if review_urls_to_fetch:
        print(f'\n开始解析 {len(review_urls_to_fetch):,} 个 review 链接...')
        total_batches = (len(review_urls_to_fetch) + batch_size - 1) // batch_size
        for i in range(0, len(review_urls_to_fetch), batch_size):
            batch = review_urls_to_fetch[i:i + batch_size]
            batch_num = i // batch_size + 1
            print(f'[Batch {batch_num}/{total_batches}] 处理 {len(batch)} 个 URL...')
            for url in tqdm(batch, desc=f'Batch {batch_num}'):
                fetch_commit_hash_from_review(url)
                time.sleep(0.1)
            if _REVIEW_CACHE_FILE:
                save_review_cache(_REVIEW_CACHE_FILE, _REVIEW_TO_HASH_CACHE)
            if i + batch_size < len(review_urls_to_fetch):
                print(f'  等待 {delay:.1f}s...')
                time.sleep(delay)
    else:
        print('没有需要从 API 获取的 review 链接')
    updated_count = 0
    failed_count = 0
    for record in records:
        for commit in record.get('src_commit_links', []):
            if commit.get('tag') == 'review' and commit.get('url') and (not commit.get('hash')):
                url = commit['url']
                commit_hash = _REVIEW_TO_HASH_CACHE.get(url)
                if commit_hash:
                    commit['hash'] = commit_hash
                    updated_count += 1
                else:
                    failed_count += 1
    print(f'\nReview 链接解析完成：')
    print(f'  - 成功提取 hash: {updated_count:,}')
    print(f'  - 提取失败: {failed_count:,}')
    return records

def extract_fix_commits_from_text(text: str, src_repo: Path) -> list[dict[str, Any]]:
    results = []
    pattern = 'The following revision refers to this bug:'
    pos = 0
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        text_after = text[pos:]
        url_match = _RE_URL.search(text_after)
        if url_match:
            url = url_match.group(0)
            if 'chromium.googlesource.com' in url:
                if 'chromium/src' in url:
                    git_match = _RE_CHROMIUM_GIT.match(url)
                    if git_match:
                        commit_hash = git_match.group(1)
                        results.append({'url': url, 'hash': commit_hash, 'source': 'issue', 'tag': 'git'})
            elif 'src.chromium.org' in url:
                svn_match = _RE_SVN.match(url)
                if svn_match:
                    svn_path = svn_match.group(1)
                    revision = svn_match.group(2)
                    git_hashes = svn_revision_to_git_hashes(svn_path, revision, src_repo)
                    if git_hashes:
                        for git_hash in git_hashes:
                            results.append({'url': url, 'hash': git_hash, 'source': 'issue', 'tag': 'svn'})
        pos += len(pattern)
    return results

def extract_project_chromium_commits(text: str) -> list[dict[str, Any]]:
    results = []
    pos = 0
    while True:
        match = _RE_PROJECT_CHROMIUM.search(text, pos)
        if not match:
            break
        start_pos = match.end()
        text_after = text[start_pos:start_pos + 2000]
        commit_match = _RE_COMMIT_HASH.search(text_after)
        if commit_match:
            commit_hash = commit_match.group(1)
            results.append({'url': None, 'hash': commit_hash, 'source': 'issue', 'tag': 'raw'})
        else:
            link_match = _RE_LINK_URL.search(text_after)
            if link_match:
                url = link_match.group(1)
                if 'chromium-review.googlesource.com' in url:
                    commit_hash = fetch_commit_hash_from_review(url)
                    results.append({'url': url, 'hash': commit_hash, 'source': 'issue', 'tag': 'review'})
                    if _REVIEW_CACHE_FILE:
                        save_review_cache(_REVIEW_CACHE_FILE, _REVIEW_TO_HASH_CACHE)
                    time.sleep(0.1)
                elif 'chromium.googlesource.com' in url:
                    git_match = _RE_CHROMIUM_GIT_SIMPLE.match(url)
                    if git_match:
                        commit_hash = git_match.group(1)
                        results.append({'url': url, 'hash': commit_hash, 'source': 'issue', 'tag': 'git'})
        pos = match.end()
    return results

def _commit_exists_in_repo(sha: str, src_repo: Path) -> bool:
    try:
        r = subprocess.run(['git', 'cat-file', '-e', sha], cwd=src_repo, capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def _read_commit_message(sha: str, src_repo: Path) -> str:
    try:
        r = subprocess.run(['git', 'log', '-1', '--format=%B', sha], cwd=src_repo, capture_output=True, timeout=5, text=True)
        return r.stdout if r.returncode == 0 else ''
    except Exception:
        return ''

def expand_cherry_pick_sources(commits: list[dict[str, Any]], src_repo: Path) -> list[dict[str, Any]]:
    existing_prefixes = {c['hash'].lower()[:12] for c in commits if c.get('hash')}
    out = list(commits)
    queue = list(commits)
    while queue:
        c = queue.pop(0)
        sha = c.get('hash')
        if not sha:
            continue
        msg = _read_commit_message(sha, src_repo)
        if not msg:
            continue
        for m in _RE_CHERRY_PICK_SOURCE.finditer(msg):
            src_sha = m.group(1).lower()
            src_prefix = src_sha[:12]
            if src_prefix in existing_prefixes:
                continue
            if not _commit_exists_in_repo(src_sha, src_repo):
                continue
            new_entry = {'url': f'https://chromium.googlesource.com/chromium/src/+/{src_sha}', 'hash': src_sha, 'source': 'issue_cherry_expanded', 'tag': 'git'}
            out.append(new_entry)
            existing_prefixes.add(src_prefix)
            queue.append(new_entry)
    return out

def process_record(record: dict[str, Any], src_repo: Path) -> dict[str, Any]:
    all_commits = {}
    for issue in record.get('issues', []):
        content = issue.get('content', {})
        desc = content.get('description', {})
        if isinstance(desc, dict):
            text = desc.get('content', '')
            commits = extract_fix_commits_from_text(text, src_repo)
            for commit in commits:
                key = f"{commit['url']}#{commit['hash']}"
                all_commits[key] = commit
            new_commits = extract_project_chromium_commits(text)
            for commit in new_commits:
                key = f"{commit['url']}#{commit['hash']}"
                all_commits[key] = commit
        for comment in content.get('comments', []):
            if isinstance(comment, dict):
                text = comment.get('content', '')
                commits = extract_fix_commits_from_text(text, src_repo)
                for commit in commits:
                    key = f"{commit['url']}#{commit['hash']}"
                    all_commits[key] = commit
                new_commits = extract_project_chromium_commits(text)
                for commit in new_commits:
                    key = f"{commit['url']}#{commit['hash']}"
                    all_commits[key] = commit
    commits_list = list(all_commits.values())
    commits_expanded = expand_cherry_pick_sources(commits_list, src_repo)
    by_hash = {}
    for c in commits_expanded:
        h = (c.get('hash') or '').lower()
        if h and h not in by_hash:
            by_hash[h] = c
    record['src_commit_links'] = list(by_hash.values())
    return record

def main():
    global _SVN_TO_GIT_CACHE, _CACHE_FILE, _SVN_COMMIT_MAP
    global _REVIEW_TO_HASH_CACHE, _REVIEW_CACHE_FILE
    parser = argparse.ArgumentParser(description='从 Chromium issue 内容中提取修复 commit 引用')
    parser.add_argument('--input', type=Path, default=Path('data/processing/chromium_cve_data.jsonl'), help='输入 JSONL 文件')
    parser.add_argument('--output', type=Path, default=Path('data/processing/chromium_cve_data.jsonl'), help='输出 JSONL 文件')
    parser.add_argument('--src-repo', type=Path, default=Path('chromium'), help='Chromium src 仓库路径')
    parser.add_argument('--svn-cache', type=Path, default=Path('cache/svn_to_git_hash.json'), help='SVN 到 Git hash 的缓存文件')
    parser.add_argument('--review-cache', type=Path, default=Path('cache/review_to_hash.json'), help='Review URL 到 commit hash 的缓存文件')
    parser.add_argument('--skip-review', action='store_true', help='跳过 review 链接的解析')
    args = parser.parse_args()
    if not args.src_repo.exists():
        print(f'错误：src 仓库路径不存在: {args.src_repo}')
        print('请使用 --src-repo 参数指定正确的路径')
        return
    _CACHE_FILE = args.svn_cache
    _SVN_TO_GIT_CACHE = load_svn_cache(_CACHE_FILE)
    print(f'从缓存加载了 {len(_SVN_TO_GIT_CACHE)} 条 SVN 映射记录')
    _SVN_COMMIT_MAP = build_svn_commit_map(args.src_repo, args.svn_cache.parent)
    _REVIEW_CACHE_FILE = args.review_cache
    _REVIEW_TO_HASH_CACHE = load_review_cache(_REVIEW_CACHE_FILE)
    print(f'从缓存加载了 {len(_REVIEW_TO_HASH_CACHE)} 条 review 映射记录')
    records = []
    with open(args.input, 'r', encoding='utf-8') as f:
        for line in f:
            records.append(json.loads(line))
    print(f'读取了 {len(records)} 条 CVE 记录')
    print(f'使用 src 仓库: {args.src_repo}')
    print(f'SVN 缓存文件: {_CACHE_FILE}')
    print(f'Review 缓存文件: {_REVIEW_CACHE_FILE}')
    results = []
    for record in tqdm(records, desc='处理 CVE 记录'):
        processed = process_record(record, args.src_repo)
        results.append(processed)
    total = len(results)
    with_commits = sum((1 for r in results if r.get('src_commit_links')))
    total_commits = sum((len(r.get('src_commit_links', [])) for r in results))
    tag_counts = {}
    for r in results:
        for c in r.get('src_commit_links', []):
            tag = c['tag']
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    git_count = tag_counts.get('git', 0)
    svn_count = tag_counts.get('svn', 0)
    raw_count = tag_counts.get('raw', 0)
    review_count = tag_counts.get('review', 0)
    print(f'\n完成！')
    print(f'  - {with_commits}/{total} CVEs 有 src_commit_links ({with_commits / total * 100:.1f}%)')
    print(f'  - 总共提取了 {total_commits:,} 个 commit 引用')
    print(f'\n旧模板统计：')
    print(f'  - Git commits (chromium/src): {git_count:,}')
    print(f'  - SVN revisions: {svn_count:,}')
    print(f'\n新模板统计：')
    print(f'  - Raw commits (复杂版本): {raw_count:,}')
    print(f'  - Review links (chromium-review): {review_count:,}')
    print(f'\n缓存统计：')
    print(f'  - SVN 缓存条目: {len(_SVN_TO_GIT_CACHE):,}')
    print(f'  - Review 缓存条目: {len(_REVIEW_TO_HASH_CACHE):,}')
    with open(args.output, 'w', encoding='utf-8') as f:
        for record in results:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
    if _CACHE_FILE:
        save_svn_cache(_CACHE_FILE, _SVN_TO_GIT_CACHE)
    if _REVIEW_CACHE_FILE:
        save_review_cache(_REVIEW_CACHE_FILE, _REVIEW_TO_HASH_CACHE)
    print(f'\n输出已保存到: {args.output}')
    print(f'SVN 缓存已保存到: {_CACHE_FILE}')
    print(f'Review 缓存已保存到: {_REVIEW_CACHE_FILE}')
if __name__ == '__main__':
    main()
