"""build_soc_graph 의 RAGFlow 기본배선 — 설정 유무에 따른 자동 주입/생략."""

from pydantic import SecretStr

from agents.graph import _default_experience, _default_retriever
from core.experience import MemoryReadGate
from core.settings import Settings


class TestDefaultRetriever:
    def test_none_without_config(self) -> None:
        assert _default_retriever(Settings()) is None

    def test_built_when_configured(self) -> None:
        s = Settings(ragflow_api_token=SecretStr("t"), ragflow_dataset_id="d")
        retriever = _default_retriever(s)
        assert retriever is not None
        assert hasattr(retriever, "aretrieve")  # ContextRetriever 계약 충족

    def test_none_when_token_only(self) -> None:
        s = Settings(ragflow_api_token=SecretStr("t"))  # dataset 없음
        assert _default_retriever(s) is None

    def test_graph_only_when_graph_enabled(self) -> None:
        s = Settings(graph_rag_enabled=True)  # RAGFlow 없음, 그래프만
        retriever = _default_retriever(s)
        assert retriever is not None
        assert hasattr(retriever, "aretrieve")

    def test_composite_when_both(self) -> None:
        from tools.graph_retriever import CompositeRetriever

        s = Settings(
            ragflow_api_token=SecretStr("t"),
            ragflow_dataset_id="d",
            graph_rag_enabled=True,
        )
        assert isinstance(_default_retriever(s), CompositeRetriever)


class TestDefaultExperience:
    def test_none_without_config(self) -> None:
        assert _default_experience(Settings()) is None

    def test_built_when_exp_dataset_configured(self) -> None:
        s = Settings(ragflow_api_token=SecretStr("t"), ragflow_exp_dataset_id="exp")
        exp = _default_experience(s)
        assert isinstance(exp, MemoryReadGate)

    def test_none_when_only_kb_dataset(self) -> None:
        s = Settings(ragflow_api_token=SecretStr("t"), ragflow_dataset_id="d")
        assert _default_experience(s) is None  # exp 데이터셋 별도 필요
