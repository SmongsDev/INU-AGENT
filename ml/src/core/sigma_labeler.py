"""ADR-0002 Sigma 룰 라벨링 평가기.

pySigma로 SigmaHQ CloudTrail 룰(.yml)을 파싱하고, pySigma가 만든 조건 AST
(ConditionAND/OR/NOT/ConditionFieldEqualsValueExpression 등)를 SIEM 쿼리로
변환하지 않고 그대로 걸어서 CloudTrail 이벤트 dict 하나하나에 불리언 매칭한다.

배경: pySigma의 표준 사용법은 백엔드(Splunk/Elastic 등)로 쿼리를 변환하는 것이지만,
이 프로젝트는 룰을 "학습 라벨 생성기"로 쓴다 — 즉 이미 확보한 로컬 JSON 로그에
직접 적용해서 0/1 라벨을 만드는 것이 목적이라 SIEM 쿼리 변환이 필요 없다.
그래서 백엔드 대신 조건 AST를 순회하는 경량 평가기를 직접 작성했다.

지원하는 값 타입: SigmaString(와일드카드 포함), SigmaRegularExpression(|re),
SigmaFieldReference(|fieldref), SigmaNull(값 없음 매칭). 이번에 선정한 10개 룰이
쓰는 modifier 범위와 일치하며, 새 룰을 추가할 때 다른 타입이 나오면
NotImplementedError로 즉시 드러난다(조용히 오탐/미탐 처리하지 않기 위함).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sigma.rule import SigmaRule
from sigma.types import SigmaFieldReference, SigmaNull, SigmaRegularExpression, SigmaString, SpecialChars


def get_nested(event: dict, field: str) -> Any:
    """'userIdentity.type' 같은 점 표기 필드 경로를 event dict에서 조회."""
    cur: Any = event
    for part in field.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def sigma_string_to_pattern(value: SigmaString) -> re.Pattern:
    """SigmaString(와일드카드 *, ? 포함)을 완전일치 정규식으로 변환."""
    parts = []
    for p in value.s:
        if p is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif p is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(str(p)))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE)


def match_leaf(event: dict, field: str, value: Any) -> bool:
    field_value = get_nested(event, field)

    if isinstance(value, SigmaNull):
        return field_value is None

    if isinstance(value, SigmaFieldReference):
        # |fieldref: 다른 필드의 "현재 값"과 비교 (예: 자기 자신에게 한 조치인지 확인).
        # starts_with/ends_with는 함께 쓰인 modifier를 나타낸다(pySigma 규약):
        #   (False, False) -> field == ref          (|fieldref)
        #   (True,  False) -> field.startswith(ref) (|fieldref|startswith)
        #   (False, True ) -> field.endswith(ref)   (|fieldref|endswith)
        #   (True,  True ) -> ref in field          (|fieldref|contains)
        # 근거: pySigma modifiers.py의 각 modifier가 세우는 플래그와
        # conversion/base.py의 convert_condition_field_eq_field 분기.
        ref_value = get_nested(event, value.field)
        if field_value is None or ref_value is None:
            return False
        haystack, needle = str(field_value), str(ref_value)
        if value.starts_with and value.ends_with:
            return needle in haystack
        if value.starts_with:
            return haystack.startswith(needle)
        if value.ends_with:
            return haystack.endswith(needle)
        return haystack == needle

    if isinstance(value, SigmaRegularExpression):
        if field_value is None:
            return False
        pattern = re.compile(value.regexp.to_plain(), re.IGNORECASE)
        return pattern.search(str(field_value)) is not None

    if isinstance(value, SigmaString):
        if field_value is None:
            return False
        return sigma_string_to_pattern(value).match(str(field_value)) is not None

    # 이번 10개 룰셋은 위 4개 타입만 사용. 다른 타입이 들어오면 조용히 넘기지 않는다.
    raise NotImplementedError(f"미지원 Sigma 값 타입: {type(value).__name__} (field={field})")


def evaluate(node: Any, event: dict) -> bool:
    cls = type(node).__name__
    if cls == "ConditionAND":
        return all(evaluate(a, event) for a in node.args)
    if cls == "ConditionOR":
        return any(evaluate(a, event) for a in node.args)
    if cls == "ConditionNOT":
        return not evaluate(node.args[0], event)
    if cls == "ConditionFieldEqualsValueExpression":
        return match_leaf(event, node.field, node.value)
    raise NotImplementedError(f"미지원 Sigma 조건 노드: {cls}")


def collect_fields(node: Any, out: set[str] | None = None) -> set[str]:
    """조건 AST가 참조하는 이벤트 필드 이름을 모두 수집.

    라벨(룰)과 특성이 같은 필드를 보고 있지 않은지 자동 검사하는 데 쓴다.
    ADR-0002의 핵심 제약이 "라벨 조건에 등장하는 필드를 특성에 넣지 않는다"인데,
    이건 사람이 기억으로 지킬 수 있는 종류의 규칙이 아니라 테스트로 강제해야 한다.
    """
    if out is None:
        out = set()
    cls = type(node).__name__
    if cls in ("ConditionAND", "ConditionOR"):
        for arg in node.args:
            collect_fields(arg, out)
    elif cls == "ConditionNOT":
        collect_fields(node.args[0], out)
    elif cls == "ConditionFieldEqualsValueExpression":
        out.add(node.field)
        # |fieldref는 비교 대상 필드도 함께 참조한다.
        if isinstance(node.value, SigmaFieldReference):
            out.add(node.value.field)
    else:
        raise NotImplementedError(f"미지원 Sigma 조건 노드: {cls}")
    return out


@dataclass
class SigmaRuleMatcher:
    rule: SigmaRule
    condition_ast: Any
    source_file: str

    @classmethod
    def from_yaml_file(cls, path: Path) -> "SigmaRuleMatcher":
        rule = SigmaRule.from_yaml(path.read_text())
        parsed_condition = rule.detection.parsed_condition[0]
        return cls(rule=rule, condition_ast=parsed_condition.parsed, source_file=path.name)

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def rule_id(self) -> str:
        return str(self.rule.id)

    @property
    def level(self) -> str:
        return str(self.rule.level).rsplit(".", 1)[-1].lower()

    @property
    def mitre_tags(self) -> list[str]:
        return [str(t) for t in self.rule.tags if str(t).startswith("attack.")]

    @property
    def referenced_fields(self) -> set[str]:
        """이 룰이 매칭에 사용하는 이벤트 필드 이름 집합."""
        return collect_fields(self.condition_ast)

    def matches(self, event: dict) -> bool:
        return evaluate(self.condition_ast, event)


def load_rules(rules_dir: Path) -> list[SigmaRuleMatcher]:
    return [SigmaRuleMatcher.from_yaml_file(p) for p in sorted(rules_dir.glob("*.yml"))]
