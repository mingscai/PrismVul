import os
import re
import json
import time
from tree_sitter import Language, Parser
import tree_sitter_cpp
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
from colorama import Fore, Style, init
multiprocessing.set_start_method('spawn', force=True)
init(autoreset=True)

def info(msg, indent=0):
    print('  ' * indent + f'{Fore.CYAN}[+] {msg}{Style.RESET_ALL}')

def success(msg, indent=0):
    print('  ' * indent + f'{Fore.GREEN}[✓] {msg}{Style.RESET_ALL}')

def warn(msg, indent=0):
    print('  ' * indent + f'{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}')

def error(msg, indent=0):
    print('  ' * indent + f'{Fore.RED}[x] {msg}{Style.RESET_ALL}')
CPP_LANGUAGE = Language(tree_sitter_cpp.language())
parser = Parser(CPP_LANGUAGE)
VALID_EXTS = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.hh', '.hxx'}

def preprocess_code(code: str) -> str:
    code = re.sub('\\b(struct|class)\\s+[A-Z_][A-Z0-9_]*\\s*\\([^)]*\\)\\s+', '\\1 ', code)
    code = re.sub('\\b(struct|class)\\s+[A-Z_][A-Z0-9_]*\\s+', '\\1 ', code)
    return code

def preprocess_preproc_conditionals(code: str) -> str:
    lines = code.splitlines(True)
    out = []
    stack = []

    def comment_line(s: str) -> str:
        if s.strip() == '':
            return s
        if s.lstrip().startswith('//'):
            return s
        return '// ' + s
    for line in lines:
        stripped = line.lstrip()
        is_if = stripped.startswith('#if') or stripped.startswith('#ifdef') or stripped.startswith('#ifndef')
        is_elif = stripped.startswith('#elif')
        is_else = stripped.startswith('#else')
        is_endif = stripped.startswith('#endif')
        if is_if:
            stack.append([True, True, True])
            out.append(comment_line(line))
            continue
        if is_elif or is_else:
            if stack:
                stack[-1][1] = False
            out.append(comment_line(line))
            continue
        if is_endif:
            if stack:
                stack.pop()
            out.append(comment_line(line))
            continue
        if not stack:
            out.append(line)
        else:
            keep = all((frame[1] for frame in stack))
            out.append(line if keep else comment_line(line))
    return ''.join(out)

def collect_name_parts_and_dtor(node, code_bytes):
    parts, is_dtor = ([], False)

    def rec(n):
        nonlocal is_dtor
        if n.type in ('parameter_list', 'compound_statement'):
            return
        if n.type == '~':
            is_dtor = True
            return
        if n.type in ('qualified_identifier', 'scoped_identifier'):
            parts.append(code_bytes[n.start_byte:n.end_byte].decode('utf8', errors='ignore'))
            return
        if n.type in ('identifier', 'field_identifier', 'operator_identifier', 'operator_name', 'type_identifier'):
            parts.append(code_bytes[n.start_byte:n.end_byte].decode('utf8', errors='ignore'))
            return
        for c in n.children:
            rec(c)
    rec(node)
    dedup = []
    for p in parts:
        if not dedup or dedup[-1] != p:
            dedup.append(p)
    return (dedup, is_dtor)

def normalize_full_name(parts, is_dtor):
    if not parts:
        return '<anonymous>'
    if is_dtor:
        parts = parts[:-1] + [f'~{parts[-1]}']
    full = '::'.join(parts).lstrip(':')
    while '::::' in full:
        full = full.replace('::::', '::')
    return full

def get_param_types(param_node, code_bytes):
    types = []
    for child in param_node.children:
        if child.type not in ('parameter_declaration', 'optional_parameter_declaration'):
            continue
        parts = []
        for c in child.children:
            if c.type == 'type_qualifier':
                parts.append(code_bytes[c.start_byte:c.end_byte].decode('utf8', errors='ignore').strip())
        type_node = child.child_by_field_name('type')
        if type_node:
            parts.append(code_bytes[type_node.start_byte:type_node.end_byte].decode('utf8', errors='ignore'))
        decl_node = child.child_by_field_name('declarator')
        if decl_node:
            decl_text = code_bytes[decl_node.start_byte:decl_node.end_byte].decode('utf8', errors='ignore')
            match = re.match('^([*&]+)', decl_text)
            if match:
                if parts:
                    parts[-1] += match.group(1)
        if len(parts) > 1:
            final = ' '.join(parts[:-1]) + ' ' + parts[-1]
        else:
            final = parts[0] if parts else ''
        final = re.sub('\\s*([*&]+)\\s*', '\\1', final)
        types.append(final.strip())
    return ','.join(types)
PARSE_TIMEOUT_SEC = float(os.environ.get('CPP_PARSER_TIMEOUT_SEC', '60'))
import warnings as _ts_warn
_ts_warn.filterwarnings('ignore', category=DeprecationWarning, module='tree_sitter.*')
parser.timeout_micros = int(PARSE_TIMEOUT_SEC * 1000000)

def extract_functions_from_code(code_bytes: bytes):
    try:
        tree = parser.parse(code_bytes)
    except ValueError:
        return []
    root = tree.root_node
    results = []

    def walk(node):
        if node.type == 'function_definition':
            type_node = node.child_by_field_name('type')
            if not (type_node and type_node.type == 'class_specifier'):
                results.append(node)
                return
        if node.type in ('declaration', 'field_declaration'):
            type_node = node.child_by_field_name('type')
            if type_node and type_node.type in ('class_specifier', 'struct_specifier'):
                for child in node.children:
                    walk(child)
                return
            if contains_function_declarator(node):
                results.append(node)
                return
        if node.type == 'ERROR':
            if contains_function_declarator(node):
                results.append(node)
        if node.type in ('class_specifier', 'struct_specifier'):
            for child in node.children:
                walk(child)
            return
        for child in node.children:
            walk(child)

    def contains_function_declarator(node):
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type == 'function_declarator':
                parent = cur.parent
                is_local = False
                p = parent
                while p:
                    if p.type in ('compound_statement', 'block_statement'):
                        is_local = True
                        break
                    if p.type == 'function_definition':
                        break
                    p = p.parent
                if is_local:
                    return False
                return True
            if cur.type in ('destructor_name', 'operator_name'):
                return True
            if cur.type in ('abstract_function_declarator', 'template_argument_list'):
                continue
            if cur.type == 'call_expression':
                try:
                    fn_node = cur.child_by_field_name('function')
                    fn_name = code_bytes[fn_node.start_byte:fn_node.end_byte].decode('utf8', errors='ignore').strip() if fn_node else None
                except:
                    fn_name = None
                cls_name = None
                p = cur
                while p:
                    if p.type in ('class_specifier', 'struct_specifier'):
                        name = p.child_by_field_name('name')
                        if name:
                            cls_name = code_bytes[name.start_byte:name.end_byte].decode('utf8', errors='ignore').strip()
                        break
                    p = p.parent
                if fn_name and cls_name and (fn_name == cls_name):
                    return True
            stack.extend(cur.children)
        return False
    walk(root)
    return results

def find_function_declarator(node, skip_nested_function_defs=False):
    stack = [node]
    while stack:
        n = stack.pop()
        if skip_nested_function_defs and n.type == 'function_definition':
            continue
        if n.type == 'function_declarator':
            if not is_inside_function_body(n):
                return n
            continue
        if n.type in ('abstract_function_declarator', 'template_argument_list'):
            continue
        stack.extend(n.children)
    return None

def is_inside_function_body(node):
    cur = node
    while cur.parent:
        if cur.parent.type == 'function_definition':
            body = cur.parent.child_by_field_name('body')
            if body and body.start_byte <= node.start_byte <= body.end_byte:
                return True
        cur = cur.parent
    return False

def get_return_type_from_ancestors(func_decl_node, code_bytes):
    ref_or_ptr = ''
    base_type = ''
    cur = func_decl_node
    while cur.parent:
        parent = cur.parent
        if parent.type in ('reference_declarator', 'pointer_declarator'):
            text = code_bytes[parent.start_byte:parent.end_byte].decode('utf8', errors='ignore').strip()
            if text and text[0] in '&*':
                ref_or_ptr = text[0]
        type_node = parent.child_by_field_name('type')
        if type_node:
            if type_node.type not in ('class_specifier', 'struct_specifier', 'union_specifier'):
                base_type = code_bytes[type_node.start_byte:type_node.end_byte].decode('utf8', errors='ignore')
                break
        cur = parent
    if not base_type:
        return ''
    return base_type + ref_or_ptr

def get_return_type_from_error_node(error_node, func_decl, code_bytes):
    children = list(error_node.children)
    try:
        idx = children.index(func_decl)
    except ValueError:
        return ''
    for i in range(idx - 1, -1, -1):
        n = children[i]
        field = error_node.field_name_for_child(i)
        if field == 'type':
            return code_bytes[n.start_byte:n.end_byte].decode('utf8', errors='ignore').strip()
        if n.type in ('qualified_identifier', 'scoped_identifier', 'type_identifier', 'primitive_type'):
            return code_bytes[n.start_byte:n.end_byte].decode('utf8', errors='ignore').strip()
    return ''

def get_function_signature(node, code_bytes):
    if node.type == 'ERROR':
        func_decl = find_function_declarator(node, skip_nested_function_defs=True)
    else:
        func_decl = find_function_declarator(node)
    if func_decl is None:
        return None
    name_node = func_decl.child_by_field_name('declarator')
    if name_node is None:
        name_node = func_decl.child_by_field_name('name') or func_decl
    parts, is_dtor = collect_name_parts_and_dtor(name_node, code_bytes)
    scope_parts = []
    cur = node
    while cur.parent:
        p = cur.parent
        if p.type in ('class_specifier', 'struct_specifier'):
            cls_name = p.child_by_field_name('name')
            if cls_name:
                scope_parts.append(code_bytes[cls_name.start_byte:cls_name.end_byte].decode('utf8', errors='ignore'))
        elif p.type == 'namespace_definition':
            ns_name = p.child_by_field_name('name')
            if ns_name:
                scope_parts.append(code_bytes[ns_name.start_byte:ns_name.end_byte].decode('utf8', errors='ignore'))
        cur = p
    if scope_parts:
        parts = scope_parts[::-1] + parts
    func_name = normalize_full_name(parts, is_dtor)
    if node.type == 'ERROR':
        ret_type = get_return_type_from_error_node(node, func_decl, code_bytes)
    else:
        ret_type = get_return_type_from_ancestors(func_decl, code_bytes)

    def get_enclosing_class_name(node):
        cur = node
        while cur:
            if cur.type in ('class_specifier', 'struct_specifier', 'union_specifier'):
                name = cur.child_by_field_name('name')
                if name:
                    return code_bytes[name.start_byte:name.end_byte].decode('utf8', errors='ignore')
            cur = cur.parent
        return None
    last_ident = parts[-1] if parts else ''
    enclosing_class_name = get_enclosing_class_name(node)
    if is_dtor or (enclosing_class_name and last_ident == enclosing_class_name):
        ret_type = ''
    params_node = func_decl.child_by_field_name('parameters')
    params_text = get_param_types(params_node, code_bytes) if params_node else ''
    if ret_type:
        return f'{func_name}:{ret_type}({params_text})'
    else:
        return f'{func_name}:({params_text})'

def find_first_compound_statement(node, skip_nested_function_defs=False):
    stack = [node]
    while stack:
        n = stack.pop()
        if skip_nested_function_defs and n.type == 'function_definition':
            continue
        if n.type == 'compound_statement':
            return n
        stack.extend(n.children)
    return None

def is_gtest_function(signature: str) -> bool:
    patterns = ['::SetUp\\(\\)', '::TearDown\\(\\)', '\\bSetUp\\(\\)', '\\bTearDown\\(\\)', '\\bTestBody\\(\\)', '\\bTEST\\b', '\\bTEST_F\\b', '\\bTEST_P\\b', '\\bTYPED_TEST\\b']
    return any((re.search(p, signature) for p in patterns))

def extract_from_file(file_path, base_path, include_code=False, exclude_gtests=False, verbose=False):
    try:
        with open(file_path, 'r', encoding='utf8', errors='ignore') as f:
            code = f.read()
    except Exception as e:
        return (None, f'read error: {e}', 0)
    try:
        clean_code = preprocess_preproc_conditionals(preprocess_code(code))
        clean_bytes = clean_code.encode('utf8')
        function_nodes = extract_functions_from_code(clean_bytes)
        results = []
        filtered_funcs = 0
        for node in function_nodes:
            signature = get_function_signature(node, clean_bytes)
            if include_code:
                if node.type == 'ERROR':
                    body = find_first_compound_statement(node, skip_nested_function_defs=True)
                    if body:
                        func_code = clean_bytes[node.start_byte:body.end_byte].decode('utf8', errors='ignore')
                    else:
                        func_code = clean_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')
                elif node.type == 'function_definition':
                    body = node.child_by_field_name('body')
                    end = body.end_byte if body else node.end_byte
                    func_code = clean_bytes[node.start_byte:end].decode('utf8', errors='ignore')
                else:
                    func_code = clean_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')
            else:
                func_code = None
            if exclude_gtests and signature:
                if is_gtest_function(signature):
                    filtered_funcs += 1
                    if verbose:
                        warn(f'Skipped GTest func in {os.path.relpath(file_path, base_path)}: {signature}', indent=2)
                    continue
            rel_path = os.path.relpath(file_path, base_path)
            results.append({'f_path': rel_path, 'f_sig': signature, 'f_code': func_code})
        return (results, None, filtered_funcs)
    except Exception as e:
        return (None, f'parse error: {e}', 0)

def process_project(project_path, num_workers=None, verbose=False, quiet=False, include_code=False, exclude_gtests=False):
    all_files = []
    test_dir_pattern = re.compile('(^|[\\\\/])(test|tests|gtest|unittest)([\\\\/]|$)', re.IGNORECASE)
    test_file_pattern = re.compile('(_test|_tests|_unittest|_integrationtest)\\.(c|cc|cpp|cxx|h|hpp|hh|hxx)$', re.IGNORECASE)
    skipped_dirs = set()
    skipped_files = []
    for root, _, files in os.walk(project_path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in VALID_EXTS:
                if exclude_gtests:
                    if test_dir_pattern.search(root):
                        skipped_dirs.add(root)
                        continue
                    if test_file_pattern.search(fname):
                        skipped_files.append(os.path.join(root, fname))
                        continue
                all_files.append(os.path.join(root, fname))
    if not quiet:
        info(f'Found {len(all_files)} source files', indent=1)
        if exclude_gtests:
            warn(f'Filtered out {len(skipped_dirs)} test directories and {len(skipped_files)} test files', indent=1)
        num_workers = num_workers or max(1, multiprocessing.cpu_count() - 1)
        info(f'Using {num_workers} parallel workers', indent=1)
        if verbose and exclude_gtests:
            for d in sorted(skipped_dirs):
                warn(f'Skipped test dir: {os.path.relpath(d, project_path)}', indent=2)
            for f in sorted(skipped_files):
                warn(f'Skipped test file: {os.path.relpath(f, project_path)}', indent=2)
    all_functions, failed_files = ([], [])
    total_filtered_funcs = 0
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(extract_from_file, fpath, project_path, include_code, exclude_gtests, verbose): fpath for fpath in all_files}
        iterator = as_completed(futures)
        if not quiet:
            iterator = tqdm(iterator, total=len(futures), ncols=100, desc='    Parsing')
        for future in iterator:
            fpath = futures[future]
            try:
                results, err, filtered_count = future.result()
                total_filtered_funcs += filtered_count
                if results:
                    all_functions.extend(results)
                    if verbose and (not quiet):
                        success(f'{os.path.relpath(fpath, project_path)} ✓', indent=2)
                elif err:
                    failed_files.append({'file': fpath, 'error': err})
                    if verbose and (not quiet):
                        warn(f'{os.path.relpath(fpath, project_path)} ✗ {err}', indent=2)
            except Exception as e:
                failed_files.append({'file': fpath, 'error': str(e)})
                if verbose and (not quiet):
                    error(f'{os.path.relpath(fpath, project_path)} ✗ {str(e)}', indent=2)
    if exclude_gtests and (not quiet):
        warn(f'Filtered out {total_filtered_funcs} GTest-related functions', indent=1)
    return (all_functions, failed_files)
if __name__ == '__main__':
    import argparse
    parser_arg = argparse.ArgumentParser(description='Extract C/C++ functions via Tree-sitter')
    parser_arg.add_argument('--repo_path', type=str, default='chromium/', help='Path to project root')
    parser_arg.add_argument('--out_path', type=str, default='utils/tree_sitter_parser_output.json', help='Output JSON file')
    parser_arg.add_argument('--fail_log', type=str, default='utils/tree_sitter_parser_failed_files.json', help='File for failed logs')
    parser_arg.add_argument('--threads', type=int, default=32, help='Number of parallel workers')
    parser_arg.add_argument('--verbose', action='store_true', help="Show each file's parse result and filtered details")
    parser_arg.add_argument('--quiet', action='store_true', help='Only show final summary')
    parser_arg.add_argument('--include-code', action='store_true', help='Worker extracts code snippets')
    parser_arg.add_argument('--exclude-gtests', action='store_true', help='Exclude Google Test related files/functions')
    args = parser_arg.parse_args()
    if not args.quiet:
        print()
        info(f'Scanning project: {args.repo_path}')
    functions, failed = process_project(args.repo_path, num_workers=args.threads, verbose=args.verbose, quiet=args.quiet, include_code=args.include_code, exclude_gtests=args.exclude_gtests)
    if not args.quiet:
        success(f'Extracted {len(functions)} functions → {args.out_path}')
    with open(args.out_path, 'w', encoding='utf8') as f:
        json.dump(functions, f, indent=2, ensure_ascii=False)
    if failed:
        with open(args.fail_log, 'w', encoding='utf8') as f:
            json.dump(failed, f, indent=2, ensure_ascii=False)
        if not args.quiet:
            warn(f'{len(failed)} files failed → {args.fail_log}', indent=1)
    elif not args.quiet:
        success('All files parsed successfully')
    if not args.quiet:
        print()
