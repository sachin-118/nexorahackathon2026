"""Data loading and validation module for ShieldLens supporting official hackathon dataset schemas."""

import csv
import json
import os
from typing import List, Optional, Union, TextIO, Dict, Any
from io import StringIO

from engine.models import Vulnerability, Profile, GoldSetEntry, WeightModifiers


class ShieldLensDataError(Exception):
    """Base exception for data loading errors."""
    pass


class FileNotFoundDataError(ShieldLensDataError):
    """Raised when a required data file is not found."""
    pass


class MissingColumnError(ShieldLensDataError):
    """Raised when required CSV columns or JSON keys are missing."""
    pass


class MalformedDataError(ShieldLensDataError):
    """Raised when file content is corrupt, unparseable, or fails type validation."""
    pass


class DataLoader:
    """Robust data loader for official ShieldLens hackathon datasets."""

    @staticmethod
    def _read_content(source: Union[str, TextIO]) -> tuple[str, str]:
        """Read content from either a file path or file-like stream. Return (content, identifier)."""
        if isinstance(source, str):
            if not os.path.exists(source):
                raise FileNotFoundDataError(f"Data file not found at path: '{source}'")
            try:
                with open(source, "r", encoding="utf-8") as f:
                    return f.read(), source
            except Exception as e:
                raise MalformedDataError(f"Unable to read file '{source}': {str(e)}")
        else:
            try:
                content = source.read()
                name = getattr(source, "name", "stream")
                return content, name
            except Exception as e:
                raise MalformedDataError(f"Unable to read stream: {str(e)}")

    @classmethod
    def load_vulnerabilities(cls, source: Union[str, TextIO]) -> List[Vulnerability]:
        """Load and validate vulnerabilities from CSV."""
        content, name = cls._read_content(source)
        if not content.strip():
            raise MalformedDataError(f"Vulnerabilities file '{name}' is empty.")

        try:
            reader = csv.DictReader(StringIO(content))
        except Exception as e:
            raise MalformedDataError(f"Failed to parse CSV file '{name}': {str(e)}")

        if not reader.fieldnames:
            raise MalformedDataError(f"CSV file '{name}' has no headers or is malformed.")

        headers = set(field.strip() for field in reader.fieldnames if field)
        
        # Check cve_id requirement
        if "cve_id" not in headers:
            raise MissingColumnError(f"Vulnerabilities file '{name}' is missing required column: 'cve_id'. Found: {sorted(list(headers))}")
        
        # Check product_name or description
        has_prod = "product_name" in headers
        has_desc = "description" in headers
        if not (has_prod or has_desc):
            raise MissingColumnError(f"Vulnerabilities file '{name}' must have either 'product_name' or 'description'. Found: {sorted(list(headers))}")

        # Check CVSS score column
        has_cvss_base = "cvss_base_score" in headers
        has_cvss = "cvss_score" in headers
        if not (has_cvss_base or has_cvss):
            raise MissingColumnError(f"Vulnerabilities file '{name}' must have either 'cvss_base_score' or 'cvss_score'. Found: {sorted(list(headers))}")

        vulnerabilities = []
        for line_num, row in enumerate(reader, start=2):
            if not any(row.values()):
                continue

            cve_id = (row.get("cve_id") or "").strip()
            product_name = (row.get("product_name") or row.get("description") or "").strip()
            raw_cvss = (row.get("cvss_base_score") or row.get("cvss_score") or "").strip()

            if not cve_id or not product_name or not raw_cvss:
                raise MalformedDataError(
                    f"Line {line_num} in '{name}' contains blank required fields: "
                    f"cve_id='{cve_id}', product_name/description='{product_name}', cvss_score='{raw_cvss}'"
                )

            try:
                cvss_score = float(raw_cvss)
            except ValueError:
                raise MalformedDataError(
                    f"Line {line_num} in '{name}' has invalid numeric cvss_score: '{raw_cvss}'"
                )

            # CISA KEV parsing
            raw_kev = (row.get("cisa_kev") or "false").strip().lower()
            cisa_kev = raw_kev in ("true", "1", "yes")

            # EPSS parsing
            raw_epss = (row.get("first_epss") or "0.0").strip()
            try:
                first_epss = float(raw_epss)
            except ValueError:
                raise MalformedDataError(
                    f"Line {line_num} in '{name}' has invalid numeric first_epss: '{raw_epss}'"
                )

            # Ranks parsing
            def _parse_opt_int(val: Optional[str]) -> Optional[int]:
                if not val or not val.strip():
                    return None
                try:
                    return int(val.strip())
                except ValueError:
                    return None

            rank_bank = _parse_opt_int(row.get("practitioner_rank_bank"))
            rank_startup = _parse_opt_int(row.get("practitioner_rank_startup"))

            # Optional list helper
            def _parse_list(val: Optional[str]) -> List[str]:
                if not val:
                    return []
                val = val.strip()
                if val.startswith("[") and val.endswith("]"):
                    try:
                        parsed = json.loads(val)
                        if isinstance(parsed, list):
                            return [str(x).strip() for x in parsed if x]
                    except json.JSONDecodeError:
                        pass
                return [x.strip() for x in val.split(";") if x.strip()]

            try:
                vuln = Vulnerability(
                    cve_id=cve_id,
                    product_name=product_name,
                    cvss_base_score=cvss_score,
                    cisa_kev=cisa_kev,
                    first_epss=first_epss,
                    title=(row.get("title") or "").strip() or None,
                    description=(row.get("description") or product_name).strip() or None,
                    severity=(row.get("severity") or "").strip() or None,
                    cvss_score=cvss_score,
                    cwe_id=(row.get("cwe_id") or "").strip() or None,
                    affected_components=_parse_list(row.get("affected_components")),
                    remediation=(row.get("remediation") or "").strip() or None,
                    references=_parse_list(row.get("references")),
                    practitioner_rank_bank=rank_bank,
                    practitioner_rank_startup=rank_startup,
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                raise MalformedDataError(f"Line {line_num} validation error in '{name}': {str(e)}")

        return vulnerabilities

    @classmethod
    def load_profiles(cls, source: Union[str, TextIO]) -> List[Profile]:
        """Load and validate target organization/environment profiles from JSON."""
        content, name = cls._read_content(source)
        if not content.strip():
            raise MalformedDataError(f"Profiles file '{name}' is empty.")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise MalformedDataError(f"Invalid JSON in profiles file '{name}': {str(e)}")

        if isinstance(data, dict):
            if "organizations" in data:
                data = data["organizations"]
            elif "profiles" in data:
                data = data["profiles"]
            else:
                data = [data]

        if not isinstance(data, list):
            raise MalformedDataError(
                f"Profiles JSON '{name}' must contain a list of profile/organization objects."
            )

        profiles = []
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                raise MalformedDataError(f"Item at index {idx} in profiles '{name}' is not a JSON object.")

            org_id = item.get("org_id") or item.get("profile_id")
            name_val = item.get("name")

            if not org_id or not name_val:
                missing = []
                if not org_id:
                    missing.append("org_id / profile_id")
                if not name_val:
                    missing.append("name")
                raise MissingColumnError(
                    f"Profile item at index {idx} in '{name}' is missing required fields: {missing}"
                )

            # Weight modifiers parsing
            weight_mods = None
            if "weight_modifiers" in item and isinstance(item["weight_modifiers"], dict):
                wm = item["weight_modifiers"]
                weight_mods = WeightModifiers(
                    cvss_weight=float(wm.get("cvss_weight", 0.0)),
                    cisa_kev_weight=float(wm.get("cisa_kev_weight", 0.0)),
                    first_epss_weight=float(wm.get("first_epss_weight", 0.0)),
                )

            try:
                profile = Profile(
                    org_id=str(org_id).strip(),
                    profile_id=str(org_id).strip(),
                    name=str(name_val).strip(),
                    sector=item.get("sector"),
                    risk_appetite=item.get("risk_appetite"),
                    weight_modifiers=weight_mods,
                    critical_products=item.get("critical_products") if isinstance(item.get("critical_products"), list) else [],
                    description=item.get("description"),
                    environment=item.get("environment"),
                    asset_criticality=item.get("asset_criticality"),
                    tech_stack=item.get("tech_stack") if isinstance(item.get("tech_stack"), list) else [],
                    network_exposure=item.get("network_exposure"),
                    compliance_requirements=item.get("compliance_requirements")
                    if isinstance(item.get("compliance_requirements"), list)
                    else [],
                )
                profiles.append(profile)
            except Exception as e:
                raise MalformedDataError(f"Profile item at index {idx} in '{name}' validation error: {str(e)}")

        return profiles

    @classmethod
    def load_gold_set(cls, source: Union[str, TextIO]) -> List[GoldSetEntry]:
        """Load and validate gold set benchmark entries from CSV."""
        content, name = cls._read_content(source)
        if not content.strip():
            raise MalformedDataError(f"Gold set file '{name}' is empty.")

        try:
            reader = csv.DictReader(StringIO(content))
        except Exception as e:
            raise MalformedDataError(f"Failed to parse CSV file '{name}': {str(e)}")

        if not reader.fieldnames:
            raise MalformedDataError(f"CSV file '{name}' has no headers or is malformed.")

        headers = set(field.strip() for field in reader.fieldnames if field)
        if "cve_id" not in headers:
            raise MissingColumnError(
                f"Gold set file '{name}' is missing required column: 'cve_id'. Found: {sorted(list(headers))}"
            )

        entries = []
        for line_num, row in enumerate(reader, start=2):
            if not any(row.values()):
                continue

            cve_id = (row.get("cve_id") or "").strip()
            product_name = (row.get("product_name") or "").strip()
            profile_id = (row.get("profile_id") or "").strip()

            if not cve_id:
                raise MalformedDataError(f"Line {line_num} in '{name}' has blank cve_id.")

            def _parse_opt_int(val: Optional[str]) -> Optional[int]:
                if not val or not val.strip():
                    return None
                try:
                    return int(val.strip())
                except ValueError:
                    return None

            rank_bank = _parse_opt_int(row.get("practitioner_rank_bank"))
            rank_startup = _parse_opt_int(row.get("practitioner_rank_startup"))

            raw_score = (row.get("expected_score") or "").strip()
            expected_score = float(raw_score) if raw_score else None

            try:
                entry = GoldSetEntry(
                    cve_id=cve_id,
                    product_name=product_name or profile_id or "N/A",
                    profile_id=profile_id or "N/A",
                    practitioner_rank_bank=rank_bank,
                    practitioner_rank_startup=rank_startup,
                    expected_risk_level=(row.get("expected_risk_level") or "").strip() or None,
                    expected_score=expected_score,
                    notes=(row.get("notes") or "").strip() or None,
                )
                entries.append(entry)
            except Exception as e:
                raise MalformedDataError(f"Line {line_num} validation error in '{name}': {str(e)}")

        return entries
