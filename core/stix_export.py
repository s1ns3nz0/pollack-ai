"""STIX 2.1 위협 인텔 생산 — DiamondEvent → 공유 bundle(NIST 800-150).

TI 를 ingest 만 하던 플랫폼이 자기 분석 산물(침입분석 다이아몬드)을 STIX 2.1 로
**생산**해 연합 방어(ISAC/파트너 SOC)와 공유한다. bundle **생성**만(외부 라이브러리 X,
공급망 표면 축소) — TAXII push(외향 발송)는 비목표.

트러스트/OPSEC:
- **victim 완전 생략**(external_minimal): 내부 자산 id/tier/임무단계 미노출 — 방어측
  자산 클래스·임무의존성 유출 방지(Codex Crit). 공유는 위협측(actor/TTP/IOC)만.
- **표준 TLP marking**(커스텀 안 만듦) + object_marking_refs. 기본 amber.
- 결정론 id: uuid5(platform ns, type+value) — OASIS ns(SCO 전용) 금지.
- 생성 전용·읽기전용·랜덤/Date.now 없음(created_at 주입). state 불변.

Spec: docs/superpowers/specs/2026-07-09-stix-ti-production-design.md
"""

from __future__ import annotations

import ipaddress
import re
from uuid import NAMESPACE_DNS, uuid5

from core.models import CampaignMatch, DiamondEvent

# 플랫폼 소유 namespace — SDO/SRO 결정론 id 용(OASIS ns 는 SCO 전용이라 미사용).
_PLATFORM_NS = uuid5(NAMESPACE_DNS, "pollack-ai.uav-soc")

# STIX 2.1 표준 TLP marking-definition 고정 id(커스텀 SMO 생성 금지 — 표준 참조만).
_TLP_MARKINGS = {
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
}

# 라벨은 하이픈으로 시작/끝 금지(RFC — 무효 도메인 IOC 공유 방지, Codex Med).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)
_HASH_ALG = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")


def _sid(otype: str, value: str) -> str:
    """STIX 결정론 id(platform ns uuid5) — 같은 (type,value) = 같은 id."""
    return f"{otype}--{uuid5(_PLATFORM_NS, f'{otype}:{value}')}"


def _ioc_pattern(value: str) -> str | None:
    """IOC 값 → STIX 2.1 패턴(strict). 판별 불가면 None(무효 pattern 회피).

    Args:
        value: 관측 IOC(IP/CIDR/도메인/해시).

    Returns:
        STIX patterning 문자열. 분류 실패 시 None(skip).
    """
    try:
        net = ipaddress.ip_network(value, strict=False)
        kind = "ipv4-addr" if net.version == 4 else "ipv6-addr"
        return f"[{kind}:value = '{value}']"
    except ValueError:
        pass
    if _HEX_RE.match(value) and len(value) in _HASH_ALG:
        return f"[file:hashes.'{_HASH_ALG[len(value)]}' = '{value}']"
    if _DOMAIN_RE.match(value):
        return f"[domain-name:value = '{value}']"
    return None


class StixExporter:
    """DiamondEvent → STIX 2.1 bundle 생성기(결정론·OPSEC 안전).

    Args:
        producer_name: 생산 주체(identity SDO name·created_by_ref).
        tlp: 공유 TLP 등급(red/amber/green/white). 기본 amber(방산 보수적).
    """

    def __init__(
        self, producer_name: str = "pollack-ai UAV SOC", tlp: str = "amber"
    ) -> None:
        self._producer = producer_name
        self._tlp_ref = _TLP_MARKINGS.get(tlp.lower(), _TLP_MARKINGS["amber"])

    def from_diamond(
        self, diamond: DiamondEvent, created_at: str
    ) -> dict[str, object] | None:
        """DiamondEvent 를 STIX 2.1 bundle 로 생산한다(victim 생략·TLP 마킹).

        Args:
            diamond: 침입분석 다이아몬드(adversary/capabilities/infrastructure).
            created_at: STIX timestamp(ISO). created/modified/valid_from(결정론).

        Returns:
            STIX 2.1 bundle(dict). 내보낼 위협 객체가 없으면 None(빈 objects 안 냄).
        """
        actor = diamond.adversary.strip()
        techs = [t for t in diamond.capabilities if t]
        iocs = [i for i in diamond.infrastructure if i]
        if not actor and not techs and not iocs:
            return None

        identity_id = _sid("identity", self._producer)
        common: dict[str, object] = {
            "spec_version": "2.1",
            "created": created_at,
            "modified": created_at,
            "created_by_ref": identity_id,
            "object_marking_refs": [self._tlp_ref],
        }
        objects: list[dict[str, object]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": created_at,
                "modified": created_at,
                "name": self._producer,
                "identity_class": "organization",
                "object_marking_refs": [self._tlp_ref],
            }
        ]

        ta_id = ""
        if actor:
            ta_id = _sid("threat-actor", actor)
            objects.append(
                {"type": "threat-actor", "id": ta_id, "name": actor, **common}
            )

        for tech in techs:
            ap_id = _sid("attack-pattern", tech)
            objects.append(
                {
                    "type": "attack-pattern",
                    "id": ap_id,
                    "name": f"MITRE ATT&CK {tech}",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": tech}
                    ],
                    **common,
                }
            )
            if ta_id:
                objects.append(self._rel(ta_id, "uses", ap_id, common))

        for ioc in iocs:
            pattern = _ioc_pattern(ioc)
            if pattern is None:
                continue  # 판별 불가 IOC — 무효 pattern 회피(skip)
            ind_id = _sid("indicator", ioc)
            objects.append(
                {
                    "type": "indicator",
                    "id": ind_id,
                    "name": f"관측 IOC: {ioc}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": created_at,
                    **common,
                }
            )
            if ta_id:
                # source_ref=indicator, indicates, target_ref=threat-actor(방향 명확).
                objects.append(self._rel(ind_id, "indicates", ta_id, common))

        # identity 만 남으면(위협 SDO/SRO 0 — IOC 전부 무효 등) 공유 가치 없음 → None.
        if len(objects) <= 1:
            return None
        return {
            "type": "bundle",
            "id": _sid("bundle", f"{actor}|{','.join(techs)}|{','.join(iocs)}"),
            "objects": objects,
        }

    def from_campaign(
        self, campaign: CampaignMatch, created_at: str
    ) -> dict[str, object] | None:
        """CampaignMatch 를 STIX 2.1 campaign SDO bundle 로 생산한다(OPSEC 안전).

        진행도(matched/total)는 objective 에 요약. **next_expected(내부 시나리오 id)
        생략** — 내부 탐지체계 노출 방지(OPSEC). chain_id 는 위협 라벨(공유 무해).

        Args:
            campaign: 진행 중 캠페인 매칭.
            created_at: STIX timestamp(created/modified).

        Returns:
            campaign SDO 담은 bundle. chain_id 없으면 None.
        """
        chain_id = campaign.chain_id.strip()
        if not chain_id:
            return None
        identity_id = _sid("identity", self._producer)
        marks = [self._tlp_ref]
        camp_id = _sid("campaign", chain_id)
        objective = f"진행 {campaign.matched}/{campaign.total} 단계(체인 {chain_id})"
        objects: list[dict[str, object]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": created_at,
                "modified": created_at,
                "name": self._producer,
                "identity_class": "organization",
                "object_marking_refs": marks,
            },
            {
                "type": "campaign",
                "spec_version": "2.1",
                "id": camp_id,
                "created": created_at,
                "modified": created_at,
                "created_by_ref": identity_id,
                "object_marking_refs": marks,
                "name": campaign.name or chain_id,
                "objective": objective,
            },
        ]
        return {
            "type": "bundle",
            "id": _sid("bundle", f"campaign:{chain_id}"),
            "objects": objects,
        }

    def _rel(
        self,
        source_ref: str,
        rel_type: str,
        target_ref: str,
        common: dict[str, object],
    ) -> dict[str, object]:
        """relationship SRO(source_ref/relationship_type/target_ref 필수)."""
        rid = _sid("relationship", f"{source_ref}|{rel_type}|{target_ref}")
        return {
            "type": "relationship",
            "id": rid,
            "relationship_type": rel_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            **common,
        }
