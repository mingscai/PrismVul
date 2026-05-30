# PrismVul

The repository has two halves: **`data_processing/`** builds the benchmark from
public CVE / issue-tracker / commit sources, and **`evaluation/`** runs the four
technique families studied in the paper (statistical, machine learning, code
retrieval, agentic LLM) against the constructed benchmark.

## Layout

```
data_processing/    Benchmark construction pipeline (01 → 25) + gumtree_differ/
evaluation/
  precompute/       Splits, GT index, retrieval corpora (run before any baseline)
  scripts/          Baseline drivers, grouped by technique family (i → iv)
  utils/            Shared library: dataset I/O, function matching, metrics,
                    agent runtime, C/C++ parser
  configs/agent_prompts/   System + task prompt templates for the agentic family
```

## Benchmark construction (`data_processing/`)

Scripts are numbered and run in order; each reads the JSONL produced by the
previous stage and writes the next. The pipeline progressively turns raw CVE
records into a dataset of vulnerabilities annotated with their ground-truth
vulnerable functions.

1. **Collect CVEs (01–05).** Download CVE records from MITRE / NVD / CVEDetails,
   merge the sources into one entry per CVE, and backfill missing CWE info.
2. **Select & classify (06–07).** Keep the target project's CVEs (Chromium) and
   resolve each to its representative CWE.
3. **CVE → issue → fix commit (08–13).** Follow references to the issue tracker,
   resolve redirects, fetch issue content, extract the fix commit(s) from each
   issue, and validate that those commits exist upstream.
4. **Extract the fix diff (14–19).** Pull diff metadata from each fix commit,
   download the changed files, keep C/C++ only, strip comments, run the GumTree
   AST differ (`gumtree_differ/`) to get function-level edits, and merge the
   resulting changed functions back into each CVE record.
5. **Process descriptions (20–23).** NLP on the CVE text: mask answer-leaking
   anchors, restate the masked description, structure it into fields, and
   summarize the linked issue report.
6. **Label & assemble (24–25).** A two-stage LLM classifies the changed
   functions into vulnerable vs. supporting (the ground truth), then commit
   chains are materialized into the final per-instance records.

The C/C++ AST differ in `gumtree_differ/` (used by stage 18) is a separate Java
project; build it once with `cd data_processing/gumtree_differ && ./gradlew build`.

## Evaluation (`evaluation/`)

First run the **`precompute/`** steps once to produce the inputs every baseline
shares: `build_splits.py` (train/val/test), `build_gt.py` (ground-truth index),
`build_function_corpus.py` (the function database for the retrieval baselines),
and `build_rag_corpus.py` (the historical-CVE corpus for the in-context agent).

Each **`scripts/`** driver then loads the dataset and a split, runs one method
over the test instances, and writes predictions + metrics under `results/`. The
four technique families are:

- **i — statistical.** `i_cwe_freq` ranks functions by how often their CWE class
  co-occurs with them in the training split.
- **ii — machine learning.** `ii_a_tfidf_knn` (TF-IDF nearest neighbours) and
  `ii_b_decision_tree` (a learned classifier over hand-crafted features).
- **iii — code retrieval.** `iii_a_bm25` (lexical) and `iii_b_coderankembed`
  (dense embeddings) retrieve candidate functions from the function corpus given
  the CVE description.
- **iv — agentic LLM.** `iv_a_agent` lets an LLM explore the checked-out repo
  with shell tools to locate the vulnerable functions; `iv_b_agent_icl` adds the
  historical-CVE corpus as an in-context retrieval resource.

All baselines score predictions with the shared fuzzy function matcher and
metrics in `utils/` (hit@k, recall@k, MRR, mAP), so results are directly
comparable across families.

## Data & external dependencies

The constructed benchmark (CVE records, commit chains, ground-truth functions)
and the precomputed retrieval corpora are **not** included here because of size;
they are released as a separate archive (see the paper's data-availability
statement). The dataset can also be regenerated from scratch by running
`data_processing/` in order against the public sources.

Two large external dependencies must be obtained separately:

- a local clone of the target project (e.g. Chromium) for the agentic baselines
  — pass its path via `--repo-path`;
- the dense retriever checkpoint (`CodeRankEmbed`) for `iii_b` — downloadable
  from its public model hub.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium   # only for the issue-tracker scraping stage
```

## Running

Every script is self-documenting via `--help`. Typical entry points:

```bash
# benchmark construction — run stages in order
python data_processing/01_download_from_mitre_nvd.py --help

# evaluation — precompute once, then run a baseline
python evaluation/precompute/build_splits.py --help
python evaluation/scripts/iii_a_bm25.py --help
python evaluation/scripts/iv_b_agent_icl.py --repo-path <project-clone> --help
```

All paths default to repository-relative locations; override them with the
documented CLI flags for your environment.
