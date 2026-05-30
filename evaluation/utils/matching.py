import os

def normalize_sig(sig: str) -> tuple[str, str, list[str]]:
    sig = sig.strip().replace('::', '.')
    name_only = _strip_return_type(sig)
    parts = [p for p in name_only.split('.') if p]
    return (sig, name_only, parts)

def _strip_return_type(sig: str) -> str:
    i = 0
    while i < len(sig):
        if sig[i] == ':':
            prev_colon = i > 0 and sig[i - 1] == ':'
            next_colon = i + 1 < len(sig) and sig[i + 1] == ':'
            if not prev_colon and (not next_colon):
                return sig[:i]
        i += 1
    return sig.split('(')[0]
_SRC_EXTS = {'.h', '.hpp', '.hxx', '.cuh', '.inc', '.cc', '.cpp', '.cxx', '.cu', '.c', '.m', '.mm'}

def _strip_src_ext(p: str) -> str:
    base, ext = os.path.splitext(p)
    return base if ext.lower() in _SRC_EXTS else p

def match_file_path(pred_file: str | None, gt_file: str) -> bool:
    if not pred_file:
        return True
    pred = pred_file.strip().replace('\\', '/').lstrip('./')
    gt = gt_file.strip().replace('\\', '/').lstrip('./')
    if pred == gt:
        return True
    if gt.endswith('/' + pred):
        return True
    if pred.endswith('/' + gt):
        return True
    if os.path.basename(pred) == os.path.basename(gt):
        return True
    p_stem = _strip_src_ext(pred)
    g_stem = _strip_src_ext(gt)
    if p_stem == g_stem:
        return True
    if g_stem.endswith('/' + p_stem):
        return True
    if p_stem.endswith('/' + g_stem):
        return True
    if os.path.basename(p_stem) == os.path.basename(g_stem):
        return True
    return False

def match_func_name(pred_parts: list[str], gt_parts: list[str]) -> bool:
    if not pred_parts or not gt_parts:
        return False
    return pred_parts[-1] == gt_parts[-1]

def match_predictions(predicted_items: list[dict | str], ground_truth_items: list[dict]) -> set[int]:
    preds = []
    for item in predicted_items:
        if isinstance(item, str):
            preds.append({'file': None, 'sig': item})
        else:
            preds.append({'file': item.get('file'), 'sig': item.get('sig', '')})
    matched_gt_indices: set[int] = set()
    for pred in preds:
        _, _, pred_parts = normalize_sig(pred['sig'])
        pred_file = pred.get('file')
        for i, gt in enumerate(ground_truth_items):
            if i in matched_gt_indices:
                continue
            _, _, gt_parts = normalize_sig(gt['sig'])
            gt_file = gt['file']
            if match_file_path(pred_file, gt_file) and match_func_name(pred_parts, gt_parts):
                matched_gt_indices.add(i)
                break
    return matched_gt_indices

def is_any_hit(predicted_items: list[dict | str], ground_truth_items: list[dict]) -> bool:
    return bool(match_predictions(predicted_items, ground_truth_items))
