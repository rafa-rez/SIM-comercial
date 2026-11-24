# SIM — Sistema de Inteligência Municipal (v5.0 Comercial)

Plataforma conversacional multi-cidade (**WhatsApp / WAHA** + **Console Institucional Web**) para consulta auditável de dados abertos municipais, indicadores fiscais e atos do Diário Oficial.

## Arquitetura & Capacidades (v5.0)
- **Multi-Tenant Multi-ERP (5 modelos de portais de MG):**
  - `caete_mg_3110004` (Caeté/MG — Cidade360 / GRP + Jornal Opinião)
  - `lagoa_da_prata_mg_3137205` (Lagoa da Prata/MG — WordPress + Dados Abertos + AMM-MG)
  - `matozinhos_mg_3141108` (Matozinhos/MG — Memory/iLAI + DiOE)
  - `governador_valadares_mg_3127701` (Governador Valadares/MG — PortalFácil / E&L + DOM)
  - `belo_horizonte_mg_3106200` (Belo Horizonte/MG — CKAN Metropolitano PBH + DOM-BH)
- **Motor Analítico & RAG:** DuckDB + Parquets ZSTD + 9 Gold Views contábeis + Busca Híbrida Okapi BM25 atomizada no Diário Oficial + Fontes Federais automáticas (IBGE, SICONFI/STN, DATASUS/SIOPS, INEP/IDEB, CGU, Receita Federal QSA).
- **UX WhatsApp (`Estilo C+ Institucional Adaptativo`):**
  - Prosa fluida humana em KPIs diretos (`1–2` linhas), bullets enxutos no Diário Oficial, e **Card Tabela PNG** automático (`>= 4` linhas) em balão único (`sendImage` com `caption`).
  - Transcrição de áudio com correção fonética municipal, memória de sessão isolada por cidade e proteção LAI/LGPD (`mask_sensitive_rows` + proteção de asteriscos em CPFs).
  - Travas comerciais B2G (Cache de 2 níveis, Rate-limit WhatsApp 20/dia, modo contingência `0` tokens com alerta admin).

## Execução Rápida
```powershell
docker compose up -d --build
```
Ou localmente com `.venv`:
```powershell
python -m sim_platform.ingestion.fleet_verifier --check-readiness
python -m pytest -q
```
