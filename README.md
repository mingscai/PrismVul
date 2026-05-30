# PrismVul

Code artifact for the paper *PrismVul: a benchmark for vulnerable-function localization in large software projects*.

This repository contains (1) the benchmark-construction pipeline that builds the dataset from public CVE/issue-tracker/commit sources, and (2) the evaluation harness for the four technique families studied in the paper (statistical, machine learning, code retrieval, agentic LLM).

> **Anonymized artifact.** This repository is released for double-blind review. Author identity, institution, and any non-anonymous hosting links have been removed.

## Layout

```
data_processing/      Benchmark construction pipeline (run scripts in numeric order, 01 → 25)
  01-05   download CVE records from MITRE / NVD / CVEDetails
  06      project-specific CVE selection (Chromium and other projects)
  07      CWE-Representative resolution
  08-11   CVE -> issue-tracker link discovery + content fetch
  12-13   fix-commit discovery + validation
  14-19   diff extraction, GumTree AST diff
  20-23   NLP on CVE descriptions (anchor masking, restatement, structuring, issue summarization)
  24      vulnerable-function identification (two-stage LLM classification)
  25      commit-chain materialization
  gumtree_differ/     Java (Gradle) AST-diff tool used by scripts 14-19

evaluation/
  scripts/            Method drivers, grouped by technique family (i-iv):
                        i             statistical (CWE-frequency)
                        ii_a, ii_b    machine learning (TF-IDF kNN, decision tree)
                        iii_a, iii_b  code retrieval (BM25, dense embedding)
                        iv_a, iv_b    agentic LLM (zero-shot, in-context retrieval)
  utils/              Shared library: dataset I/O, fuzzy function matching,
                      metrics, the agent runtime, the C/C++ parser.
  precompute/         GT index, train/val/test split, the function corpus and
                      the historical-CVE RAG index.
  configs/agent_prompts/   System + task prompt templates for the agentic family.
```

## Data

The constructed benchmark (CVE records, commit chains, ground-truth vulnerable
functions) and the precomputed retrieval corpus are **not** included in this
repository because of size. They are released as a separate archive; see the
data-availability statement in the paper. Each pipeline / evaluation script
documents the input/output JSONL schema it expects in its module docstring, so
the dataset can also be regenerated from scratch by running `data_processing/`
in numbered stage order against the public source projects.

Two large external dependencies are also required and must be obtained
separately:

- a local clone of the target project repository (e.g. Chromium) for the
  agentic baselines — pass its path via `--repo-path`;
- the dense retriever / reranker checkpoints (`CodeRankEmbed`, `CodeRankLLM`)
  for the code-retrieval baselines — downloadable from their public model hubs.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium   # only for the issue-tracker scraping stage
```

The GumTree AST-diff tool builds with Gradle:

```bash
cd data_processing/gumtree_differ && ./gradlew build
```

## Running

Each script is self-documenting via `--help` and a module-level docstring.
Typical evaluation entry points:

```bash
# code-retrieval baseline (BM25)
python evaluation/scripts/iii_a_bm25.py --help

# agentic baseline (zero-shot)
python evaluation/scripts/iv_a_agent.py --repo-path <project-clone> --help

# agentic baseline with in-context historical-CVE retrieval
python evaluation/scripts/iv_b_agent_icl.py --repo-path <project-clone> --help
```

All paths default to repository-relative locations; override them with the
documented CLI flags for your environment.
