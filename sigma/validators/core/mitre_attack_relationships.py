from dataclasses import dataclass
from typing import ClassVar, List, Set, Union
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaTagValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)
from sigma.data.mitre_attack import (
    mitre_attack_techniques_tactics_mapping,
    mitre_attack_tactics,
)
import re


@dataclass
class MITREATTACKTechniqueTacticMismatchIssue(SigmaValidationIssue):
    description: ClassVar[str] = "MITRE ATT&CK technique is not correctly associated with its corresponding tactic"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    technique: SigmaRuleTag
    tactic: SigmaRuleTag
    expected_tactics: List[str]


@dataclass
class MITREATTACKOrphanedTechniqueIssue(SigmaValidationIssue):
    description: ClassVar[str] = "MITRE ATT&CK technique found without corresponding tactic tag"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    technique: SigmaRuleTag
    expected_tactics: List[str]


@dataclass
class MITREATTACKOrphanedTacticIssue(SigmaValidationIssue):
    description: ClassVar[str] = "MITRE ATT&CK tactic found without corresponding technique tag"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tactic: SigmaRuleTag


class MITREATTACKTechniqueTacticRelationshipValidator(SigmaRuleValidator):
    """
    Validates that MITRE ATT&CK techniques are correctly associated with their corresponding tactics
    in Sigma rule tags. This validator checks:
    
    1. When both technique and tactic tags are present, they must be compatible
    2. Techniques should have at least one corresponding tactic (optional warning)
    3. Tactics should have at least one corresponding technique (optional warning)
    
    The validator uses the mitre_attack_techniques_tactics_mapping to verify relationships.
    """

    def __init__(self, require_technique_tactic_pairs: bool = False):
        """
        Initialize the validator.
        
        :param require_technique_tactic_pairs: If True, require that every technique has a 
               corresponding tactic and vice versa. If False, only validate relationships 
               when both are present.
        """
        self.require_technique_tactic_pairs = require_technique_tactic_pairs

    def validate(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> List[SigmaValidationIssue]:
        super().validate(rule)
        issues: List[SigmaValidationIssue] = []
        
        # Extract MITRE ATT&CK tags
        attack_tags = [tag for tag in rule.tags if tag.namespace == "attack"]
        
        if not attack_tags:
            return issues
        
        # Separate techniques and tactics
        techniques = []
        tactics = []
        
        # Tactic IDs and names (tactics dict has TA IDs as keys, names as values)
        tactic_names = set(mitre_attack_tactics.values())  # e.g., {"initial-access", "execution", ...}
        
        for tag in attack_tags:
            tag_name = tag.name.lower()
            
            # Check if it's a technique (starts with T followed by digits)
            if re.match(r'^t\d+', tag_name):
                # Convert to uppercase for lookup in mapping
                technique_id = tag_name.upper()
                techniques.append((tag, technique_id))
            # Check if it's a tactic name
            elif tag_name in tactic_names:
                tactics.append(tag)
        
        # Validate technique-tactic relationships
        issues.extend(self._validate_technique_tactic_relationships(techniques, tactics))
        
        # Optional: Check for orphaned techniques/tactics
        if self.require_technique_tactic_pairs:
            issues.extend(self._validate_orphaned_tags(techniques, tactics))
        
        return issues

    def _validate_technique_tactic_relationships(
        self, 
        techniques: List[tuple], 
        tactics: List[SigmaRuleTag]
    ) -> List[SigmaValidationIssue]:
        """Validate that techniques and tactics are correctly associated."""
        issues: List[SigmaValidationIssue] = []
        
        # Get tactic names from tags
        present_tactic_names = {tag.name.lower() for tag in tactics}
        
        for technique_tag, technique_id in techniques:
            # Look up expected tactics for this technique
            expected_tactics = mitre_attack_techniques_tactics_mapping.get(technique_id, [])
            
            if not expected_tactics:
                # Technique not found in mapping - this should be caught by ATTACKTagValidator
                continue
            
            # Check if any of the present tactics match the expected ones
            if present_tactic_names:
                matching_tactics = present_tactic_names.intersection(set(expected_tactics))
                if not matching_tactics:
                    # Find the mismatched tactic tags for reporting
                    for tactic_tag in tactics:
                        if tactic_tag.name.lower() not in expected_tactics:
                            issues.append(
                                MITREATTACKTechniqueTacticMismatchIssue(
                                    [self.rule],
                                    technique_tag,
                                    tactic_tag,
                                    expected_tactics
                                )
                            )
        
        return issues

    def _validate_orphaned_tags(
        self, 
        techniques: List[tuple], 
        tactics: List[SigmaRuleTag]
    ) -> List[SigmaValidationIssue]:
        """Check for techniques without tactics and tactics without techniques."""
        issues: List[SigmaValidationIssue] = []
        
        present_tactic_names = {tag.name.lower() for tag in tactics}
        
        # Check for techniques without corresponding tactics
        for technique_tag, technique_id in techniques:
            expected_tactics = mitre_attack_techniques_tactics_mapping.get(technique_id, [])
            if expected_tactics and not present_tactic_names.intersection(set(expected_tactics)):
                issues.append(
                    MITREATTACKOrphanedTechniqueIssue(
                        [self.rule],
                        technique_tag,
                        expected_tactics
                    )
                )
        
        # Check for tactics without corresponding techniques
        for tactic_tag in tactics:
            tactic_name = tactic_tag.name.lower()
            # Find if any present technique supports this tactic
            supporting_techniques = [
                tech_id for tech_id, tactic_list in mitre_attack_techniques_tactics_mapping.items()
                if tactic_name in tactic_list
            ]
            
            present_technique_ids = [tech_id for _, tech_id in techniques]
            if supporting_techniques and not any(tech_id in supporting_techniques for tech_id in present_technique_ids):
                issues.append(
                    MITREATTACKOrphanedTacticIssue(
                        [self.rule],
                        tactic_tag
                    )
                )
        
        return issues


class MITREATTACKStrictTechniqueTacticRelationshipValidator(MITREATTACKTechniqueTacticRelationshipValidator):
    """
    Strict version that requires technique-tactic pairs and reports orphaned tags.
    """
    
    def __init__(self):
        super().__init__(require_technique_tactic_pairs=True)