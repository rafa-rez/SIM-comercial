# AGENTS.md — SIM Comercial (v5.0)

Leia este arquivo e [`sim_platform/ATTENTION_POINTS.md`](sim_platform/ATTENTION_POINTS.md) antes de qualquer alteração na plataforma.

## Gate Obrigatório Pós-Mudança
```powershell
python -m sim_platform.ingestion.fleet_verifier --check-readiness
python -m pytest -q
```

## Documentação Técnica
- [`sim_platform/ATTENTION_POINTS.md`](sim_platform/ATTENTION_POINTS.md) — Invariantes contábeis, multi-cidade, LGPD/LAI e UX WhatsApp (`F1`–`F13`).
- [`docs/SIM.md`](docs/SIM.md) — Arquitetura do sistema.
