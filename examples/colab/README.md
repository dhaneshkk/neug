# Colab: VisionGuard360 site graph + agent memory on the hardened fork

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/dhaneshkk/neug/blob/security/review-fixes/examples/colab/neug_vg360_agent_memory.ipynb)

A single-cell notebook that installs this fork's wheel from the
[`fork-wheels`](https://github.com/dhaneshkk/neug/releases/tag/fork-wheels) release
(Linux x86_64, CPython 3.11–3.13, `vector_search` and `fts` bundled) and runs:

1. **Security probes**: `UNINSTALL '../..'` path traversal and `INSTALL ... FROM` an
   unlisted repository are both rejected.
2. **Lean 4 proofs**: transaction atomicity, integer reciprocal-rank-fusion monotonicity,
   2-hop alert monotonicity under inserts, and MCC numerator properties. The real Lean
   compiler checks them, and each has a runtime mirror in the notebook.
3. **VisionGuard360**: a rig → zone → camera → equipment → permit → incident graph with
   *incidents within 2 hops of a hot-work permit* (checked against an independent BFS),
   a zone risk board, atomic camera-detection ingest with injected crashes, and
   detection → past-incident matching (HNSW + graph fusion) scored with MCC.
4. **Agent memory**: entities and relations, episodic embeddings, BM25 keyword recall,
   atomic writes with fact supersession, durability across reopen, and hybrid recall
   scored with MCC.

Text encoders are trained with Sharpness-Aware Minimization (numpy, no GPU needed).
Set `OPENAI_BASE_URL` / `OPENAI_API_KEY` / `OPENAI_MODEL` (env vars or Colab secrets)
to use an OpenAI-compatible `/chat/completions` endpoint for the STOP-WORK brief and
memory answers. Without them, the notebook uses offline fallbacks.

All data is synthetic.
