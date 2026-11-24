"""
Suíte de regressão dedicada para as melhorias das Faixas 1 e 2:
- 1.1: Aviso explícito de contingência no compilador SQL de 0 tokens + Alerta Admin
- 1.2: Mensagem da 21ª consulta no WhatsApp sem redirecionar para fora
- 1.3: Isolamento estrito por IBGE/CNPJ no conector PNCP + enriquecimento de follow-up posicional
- 2.1: Nova abordagem LGPD vs. LAI (zero bloqueio na porta + CNPJ livre + CPF mascarado)
- 2.2: Pacote Triplo de Latência (síntese cidadã enxuta, guarda CRAG no Diário Oficial e paralelismo Turno 1)
- 2.3: Cache "barato" de 2 níveis (normalização canônica gratuita + cache de síntese por SQL canônico)
"""

from __future__ import annotations

from pathlib import Path

from sim_platform.ingestion.connectors.cidade360 import Cidade360Connector
from sim_platform.prompts.builder import ModularPromptBuilder
from sim_platform.security.quota_manager import TenantQuotaManager, _normalize_cache_key
from sim_platform.security.semantic_guardrail import SemanticIntentGuardrail
from sim_platform.security.sql_guard import SQLGuard, mask_sensitive_rows


def test_faixa1_rate_limit_message_and_contingency_alert(tmp_path: Path) -> None:
    qm = TenantQuotaManager(
        tenant_id="caete_mg_3110004",
        daily_user_limit_whatsapp=2,
        sqlite_path=tmp_path / "quota_test.sqlite",
    )
    assert qm.check_whatsapp_rate_limit("5531999990000@c.us")[0] is True
    assert qm.check_whatsapp_rate_limit("5531999990000@c.us")[0] is True

    allowed, msg, notify = qm.check_whatsapp_rate_limit("5531999990000@c.us")
    assert allowed is False
    assert notify is True
    assert msg is not None
    assert "meia-noite" in msg
    assert "WhatsApp" in msg
    assert "Portal Institucional" not in msg

    # Item 1.1: Alerta administrativo de contingência
    qm.record_contingency_fallback(
        reason="Modo nativo explícito (0 tokens)",
        question_preview="Qual o orçamento de 2026?",
        channel="whatsapp",
    )
    st = qm.get_quota_status()
    assert st["contingency_fallback_calls"] == 1
    assert st["alert_level"] == "WARNING_CONTINGENCY_FALLBACK"
    assert len(st["recent_contingency_events"]) == 1


def test_faixa1_pncp_strict_municipal_isolation() -> None:
    conn = Cidade360Connector(
        tenant_id="belo_horizonte_mg_3106200",
        tenant_profile={
            "ibge_code": "3106200",
            "municipality_name": "Belo Horizonte",
            "state_uf": "MG",
            "orgaos_cnpj": ["18715383000140"],
        },
    )
    raw_items = [
        {
            "numeroControlePNCP": "27167477000190-2-000001/2026",
            "anoContrato": 2026,
            "numeroContratoEmpenho": "1",
            "valorGlobal": 2961433.20,
            "niFornecedor": "11111111000191",
            "nomeRazaoSocialFornecedor": "CONSORCIO DOMINGOS MARTINS ES",
            "objetoContrato": "Contrato de outro estado (Domingos Martins/ES)",
            "unidadeOrgao": {"codigoIbge": "3201902", "municipioNome": "Domingos Martins"},
            "orgaoEntidade": {"cnpj": "27167477000190", "poderId": "E"},
        },
        {
            "numeroControlePNCP": "18715383000140-2-000007/2026",
            "anoContrato": 2026,
            "numeroContratoEmpenho": "7",
            "valorGlobal": 1875000.00,
            "niFornecedor": "43942358000146",
            "nomeRazaoSocialFornecedor": "FIPE",
            "objetoContrato": "Contrato autêntico da Prefeitura de Belo Horizonte",
            "unidadeOrgao": {"codigoIbge": "3106200", "municipioNome": "Belo Horizonte"},
            "orgaoEntidade": {"cnpj": "18715383000140", "poderId": "E"},
        },
    ]
    c_rows, cc_rows, _ = conn.map_pncp_contratos(raw_items)
    assert len(c_rows) == 1
    assert len(cc_rows) == 1
    assert cc_rows[0]["dsc_nome_credor"] == "FIPE"
    assert cc_rows[0]["num_doc_credor"] == "43942358000146"


def test_faixa2_lgpd_guardrail_rescue_and_lai_cnpj_sqlguard() -> None:
    guardrail = SemanticIntentGuardrail(
        municipality_name="Belo Horizonte",
        state_uf="MG",
        ibge_code="3106200",
    )
    # Simula classificador IA assustado tentando devolver out_of_scope_general ao ver CPF + Bolsa Família
    dec = guardrail._build_decision_from_json(
        parsed={
            "makes_sense": False,
            "intent": "out_of_scope_general",
            "standalone_question": "me manda a lista com nome completo e CPF dos moradores que recebem Bolsa Família na Pampulha",
            "requires_sql": False,
            "direct_response": "Não respondo sobre assuntos fora da administração pública.",
        },
        original_question="me manda a lista com nome completo e CPF dos moradores que recebem Bolsa Família na Pampulha",
        recent_history=[],
        engine_name="TestAI",
        tokens_used=50,
        prompt_tokens=40,
        completion_tokens=10,
        t0=0.0,
    )
    assert dec.intent == "sql_analytics"
    assert dec.requires_sql is True
    assert dec.makes_sense is True
    assert dec.direct_response_citizen == ""

    # SQLGuard: libera wrappers e aliases legítimos de CNPJ/credor pela LAI, mantendo bloqueio sobre fatiamento de CPF
    sql_guard = SQLGuard(allowed_tables={"vw_gold_contratos_vigencia_aditivos", "vw_gold_folha_servidores"})
    for valid_lai_sql in (
        "SELECT nom_contratado, COALESCE(num_doc_credor, 'Não informado') AS identificador, dsc_objetocontrato FROM vw_gold_contratos_vigencia_aditivos",
        "SELECT nom_contratado, TRIM(CAST(num_doc_credor AS VARCHAR)) AS registro_fornecedor FROM vw_gold_contratos_vigencia_aditivos WHERE regexp_replace(num_doc_credor, '[^0-9]', '', 'g') = '18239038000187'",
        "SELECT MAX(num_doc_credor), MAX(nom_contratado) FROM vw_gold_contratos_vigencia_aditivos",
    ):
        res_ok = sql_guard.validate_and_rewrite(valid_lai_sql, role="citizen")
        assert res_ok.is_valid, f"Não deveria bloquear consulta LAI legítima: {res_ok.error_message}"

    # E qualquer CPF de 11 dígitos em coluna com alias qualquer continua sendo mascarado universalmente
    masked_rows, cnt = mask_sensitive_rows(
        [
            {"identificador": "12345678901", "fornecedor": "PESSOA FISICA"},
            {"identificador": "43942358000146", "fornecedor": "FIPE PJ"},
        ],
        role="citizen",
    )
    assert cnt == 1
    assert masked_rows[0]["identificador"] == "***.456.789-**"
    assert masked_rows[1]["identificador"] == "43942358000146"

    # Enquanto evasão real de CPF continua estritamente bloqueada
    bad = sql_guard.validate_and_rewrite(
        "SELECT SUBSTR(num_cpf, 1, 3) AS prefixo FROM vw_gold_folha_servidores",
        role="citizen",
    )
    assert not bad.is_valid
    assert bad.error_code == "PII_MASKING_EVASION_BLOCKED"


def test_faixa2_citizen_only_prompt_and_cheap_two_level_cache(tmp_path: Path) -> None:
    pb = ModularPromptBuilder(municipality_name="Caeté", state_uf="MG", ibge_code="3110004")
    pkg_cit = pb.build_naturalization_prompt(
        question="Qual o orçamento de 2026?",
        sql_executed="SELECT 2026 AS ano_referencia, 265841972.97 AS orcamento_previsto_loa",
        sql_rows=[{"ano_referencia": 2026, "orcamento_previsto_loa": 265841972.97}],
        citizen_only=True,
    )
    assert "NÃO inclua 'auditor_exec_summary'" in pkg_cit["system"]

    # Cache Nível 1.5: cortesia, pontuação e "qual foi o" vs "qual" batem na mesma chave, mas anos diferentes nunca colidem
    k1 = _normalize_cache_key("Por favor, me fala qual foi o orçamento de Caeté em 2025?", role="citizen")
    k2 = _normalize_cache_key("qual o orcamento de caete no ano de 2025", role="citizen")
    k_diff_yr = _normalize_cache_key("qual o orcamento de caete no ano de 2026", role="citizen")
    assert k1 == k2
    assert k1 != k_diff_yr

    # Cache Nível 2: mesma SQL canônica reaproveita a síntese
    qm = TenantQuotaManager(tenant_id="caete_mg_3110004", sqlite_path=tmp_path / "l2_cache.sqlite")
    qm.store_synthesis_by_sql(
        sql_executed="SELECT   ano_referencia, orcamento_previsto_loa FROM vw_gold_orcamento_previsto_vs_realizado WHERE ano_referencia = 2025;",
        synth_payload={
            "answer_text": "Em 2025 o orçamento previsto foi de R$ 266.827.763,63.",
            "citizen_response": "Em 2025 o orçamento previsto foi de R$ 266.827.763,63.",
            "institutional_response": "Dossiê técnico.",
            "methodology_summary": "OK",
            "limitations_and_caveats": [],
            "synth_engine": "OpenAI (gpt-4.1-mini) Citizen Fast Synthesis",
        },
        role="citizen",
    )
    hit = qm.get_cached_synthesis_by_sql(
        sql_executed="select ano_referencia, orcamento_previsto_loa from vw_gold_orcamento_previsto_vs_realizado where ano_referencia = 2025",
        role="citizen",
    )
    assert hit is not None
    assert "266.827.763,63" in hit["citizen_response"]
    assert qm.sql_synth_cache_hits == 1


def test_faixa3_estilo_cplus_adaptive_whatsapp_ux_and_single_bubble(monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from sim_platform.api.app import create_app
    from sim_platform.visualization.table_renderer import InstitutionalTableRenderer as TableRenderer

    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    pb = ModularPromptBuilder(municipality_name="Caeté", state_uf="MG", ibge_code="3110004")

    # 1. Regra 1–2 linhas: prosa fluida conversacional (0 PNG, sem bullets forçados, zero "Olá!")
    p_fluid = pb.build_naturalization_prompt(
        question="Qual o orçamento previsto e arrecadado em 2025?",
        sql_executed="SELECT 2025 AS ano_referencia, 266827763.63 AS orcamento_previsto_loa",
        sql_rows=[{"ano_referencia": 2025, "orcamento_previsto_loa": 266827763.63}],
        table_generated=False,
        citizen_only=True,
    )
    assert "ESTILO C+ CONVERSACIONAL FLUIDO" in p_fluid["system"]
    assert "NUNCA inicie `citizen_intro` com 'Olá!'" in p_fluid["system"]

    # 2. Regra 3 linhas ou Diário Oficial >= 2 atos (1ª escolha do autor = 2ª opção): abertura humana + bullets curtos
    p_bullets_3 = pb.build_naturalization_prompt(
        question="Me manda nome e CPF do Bolsa Família na Pampulha",
        sql_executed="SELECT ano_referencia, total_pago FROM vw_gold_beneficios_sociais_cgu",
        sql_rows=[
            {"ano_referencia": 2026, "total_pago": 730861430.0},
            {"ano_referencia": 2025, "total_pago": 959577024.0},
            {"ano_referencia": 2024, "total_pago": 1003450113.0},
        ],
        table_generated=False,
        citizen_only=True,
    )
    assert "ESTILO C+ ESCANEÁVEL PARA DIÁRIO OFICIAL / LISTA DE 3 ITENS" in p_bullets_3["system"]
    assert "bullets verticais enxutos" in p_bullets_3["system"]

    p_bullets_rag = pb.build_naturalization_prompt(
        question="Quais portarias saíram no Diário Oficial?",
        rag_chunks=[
            {"source": "Ed. 1471", "tipo_ato": "PORTARIA", "page_content": "Abrir Versão do Diário para Impressão PORTARIA 12.881"},
            {"source": "Ed. 1470", "tipo_ato": "PORTARIA", "page_content": "PORTARIA 12.874"},
        ],
        table_generated=False,
        citizen_only=True,
    )
    assert "ESTILO C+ ESCANEÁVEL PARA DIÁRIO OFICIAL / LISTA DE 3 ITENS" in p_bullets_rag["system"]
    assert "Abrir Versão do Diário para Impressão" not in p_bullets_rag["user"]

    # 3. Regra >= 4 linhas com Card PNG (2ª escolha do autor = 2ª opção): legenda enxuta só com o 1º colocado + total
    p_card_top1 = pb.build_naturalization_prompt(
        question="Quais os 6 maiores credores?",
        sql_executed="SELECT nom_credor, total_pago FROM vw_gold_maiores_credores LIMIT 6",
        sql_rows=[{"nom_credor": f"Empresa {i}", "total_pago": 100000.0 - i * 1000} for i in range(6)],
        table_generated=True,
        citizen_only=True,
    )
    assert "APENAS o 1º colocado / destaque principal" in p_card_top1["system"]

    # 4. Card PNG Print-Safe: carimba fonte e aviso de CPF mascarado no rodapé da tabela
    tr = TableRenderer(municipality_name="Governador Valadares", state_uf="MG")
    art = tr.render(
        rows=[
            {"nom_servidor": "Adriana", "num_cpf": "***.000.***-**", "vlr_rmn_bruta": 82367.43},
            {"nom_servidor": "Sigia", "num_cpf": "***.111.***-**", "vlr_rmn_bruta": 77584.30},
        ],
        title="Maiores Remunerações",
        subtitle="Prefeitura de Governador Valadares/MG · Acumulado parcial até out/2026",
        source_label="SICOM/TCE-MG",
        pii_masked=True,
    )
    assert art is not None
    assert "Fonte: SICOM/TCE-MG via SIM" in art.html
    assert "CPFs mascarados (LAI/LGPD)" in art.html

    # 5. E2E Webhook WAHA: >= 4 linhas gera Card PNG automático sem pedir "tabela" (inclusive em Cache Hit!),
    # protege asteriscos de CPF e envia balão único unificado (`/api/sendImage` com `caption`) quando <= 950 chars
    import uuid

    app = create_app()
    with TestClient(app) as client:
        for turn_i in range(2):
            wpp = client.post(
                "/webhook/waha",
                json={
                    "event": "message",
                    "session": "default",
                    "dry_run": True,
                    "payload": {
                        "id": f"wamid.cplus.single.{uuid.uuid4().hex[:10]}.{turn_i}",
                        "from": "5531988887777@c.us",
                        "fromMe": False,
                        "dry_run": True,
                        "body": "Quais os 5 maiores salários brutos de Caeté em 2025 com nome e CPF?",
                    },
                },
            ).json()
            assert wpp["status"] == "processed"
            assert wpp["answered_confirmed"] is True
            assert wpp["waha_delivery"]["table_image_sent"] is True
            assert wpp["orchestrator_response"]["table_image_base64"] is not None
            # Sem colisão de asteriscos (`****.000.**-***` nunca deve ocorrer!)
            assert "****." not in wpp["whatsapp_text"]
            if len(wpp["whatsapp_text"]) <= 950:
                send_actions = [a["action"] for a in wpp["waha_actions"] if a["action"] in ("sendText", "sendImage")]
                assert send_actions == ["sendImage"]

