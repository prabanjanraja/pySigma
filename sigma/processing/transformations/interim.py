import re
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.conditions import ConditionAND, ConditionOR
from sigma.types import SigmaString, SigmaNumber
from sigma.modifiers import (
    SigmaContainsModifier,
    SigmaStartswithModifier,
    SigmaEndswithModifier,
)

class TargetObjectTransformation(DetectionItemTransformation):
    """
    Transforms a TargetObject field into a combination of ObjectName and OBJECTVALUENAME,
    handling various modifiers.
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> SigmaDetectionItem:
        if detection_item.field != "TargetObject":
            return detection_item

        if not detection_item.value:
            return detection_item

        # Ensure we have a list of values to work with
        if not isinstance(detection_item.value, list):
            values = [detection_item.value]
        else:
            values = detection_item.value

        # Filter for SigmaString values only
        string_values = [v for v in values if isinstance(v, SigmaString)]
        if not string_values:
            return detection_item

        modifiers = detection_item.modifiers

        # Collect values by transformation type to reduce redundancy
        object_names = []
        object_values = []
        object_name_startswith = []
        object_value_startswith = []
        object_name_endswith = []
        object_value_endswith = []
        object_name_contains = []
        object_value_contains = []
        compound_contains = []  # For values with backslash using endswith/startswith pattern

        for sigma_string in string_values:
            s_value = str(sigma_string)

            # Equals (no modifier)
            if not modifiers:
                object_name, object_value = s_value.rsplit("\\", 1)
                if object_name != '*':  # Only add if name_part is not '*'
                    object_names.append(SigmaString(object_name))
                    object_values.append(SigmaString(object_value))

            # StartsWith
            elif SigmaStartswithModifier in modifiers:
                name_part, value_part = s_value.rsplit("\\", 1)
                if name_part != '*':  # Only split if name_part is not '*'
                    object_names.append(SigmaString(name_part))
                    object_value_startswith.append(SigmaString(value_part))
                else:
                    object_name_startswith.append(SigmaString(s_value))

            # EndsWith
            elif SigmaEndswithModifier in modifiers:
                name_part, value_part = s_value.rsplit("\\", 1)
                if name_part != '*':  # Only split if name_part is not '*'
                    object_name_endswith.append(SigmaString(name_part))
                    object_values.append(SigmaString(value_part))
                else:
                    object_value_endswith.append(SigmaString(value_part))

            # Contains
            elif SigmaContainsModifier in modifiers:
                name_part, value_part = s_value.rsplit("\\", 1)
                if name_part != '*':  # Only create compound if name_part is not '*'
                    compound_contains.append((SigmaString(name_part), SigmaString(value_part)))
                else:
                    object_name_contains.append(SigmaString(s_value))
                    object_value_contains.append(SigmaString(s_value))

        # Build consolidated transformations
        transformed_items = []

        # Add consolidated object names and values
        if object_names:
            transformed_items.append(SigmaDetectionItem("ObjectName", [], value=object_names))
        if object_values:
            transformed_items.append(SigmaDetectionItem("OBJECTVALUENAME", [], value=object_values))
        if object_name_startswith:
            transformed_items.append(SigmaDetectionItem("ObjectName", [SigmaStartswithModifier], value=object_name_startswith))
        if object_value_startswith:
            transformed_items.append(SigmaDetectionItem("OBJECTVALUENAME", [SigmaStartswithModifier], value=object_value_startswith))
        if object_name_endswith:
            transformed_items.append(SigmaDetectionItem("ObjectName", [SigmaEndswithModifier], value=object_name_endswith))
        if object_value_endswith:
            transformed_items.append(SigmaDetectionItem("OBJECTVALUENAME", [SigmaEndswithModifier], value=object_value_endswith))
        if object_name_contains:
            transformed_items.append(SigmaDetectionItem("ObjectName", [SigmaContainsModifier], value=object_name_contains))
        if object_value_contains:
            transformed_items.append(SigmaDetectionItem("OBJECTVALUENAME", [SigmaContainsModifier], value=object_value_contains))

        # Handle compound contains transformations (backslash values)
        compound_transformations = []
        for name_part, value_part in compound_contains:
            compound_transformations.append(SigmaDetection(
                detection_items=[
                    SigmaDetectionItem("ObjectName", [SigmaEndswithModifier], value=[name_part]),
                    SigmaDetectionItem("OBJECTVALUENAME", [SigmaStartswithModifier], value=[value_part]),
                ],
                item_linking=ConditionAND,
            ))

        # Combine all transformations
        all_transformations = []
        
        # For equals, startswith, and endswith: combine ObjectName and OBJECTVALUENAME with AND
        if (object_names or object_name_startswith or object_name_endswith) and \
           (object_values or object_value_startswith or object_value_endswith):
            name_items = []
            value_items = []
            
            if object_names:
                name_items.append(SigmaDetectionItem("ObjectName", [], value=object_names))
            if object_name_startswith:
                name_items.append(SigmaDetectionItem("ObjectName", [SigmaStartswithModifier], value=object_name_startswith))
            if object_name_endswith:
                name_items.append(SigmaDetectionItem("ObjectName", [SigmaEndswithModifier], value=object_name_endswith))
            
            if object_values:
                value_items.append(SigmaDetectionItem("OBJECTVALUENAME", [], value=object_values))
            if object_value_startswith:
                value_items.append(SigmaDetectionItem("OBJECTVALUENAME", [SigmaStartswithModifier], value=object_value_startswith))
            if object_value_endswith:
                value_items.append(SigmaDetectionItem("OBJECTVALUENAME", [SigmaEndswithModifier], value=object_value_endswith))

            # Combine name items with OR, value items with OR, then combine both with AND
            combined_items = []
            if len(name_items) == 1:
                combined_items.append(name_items[0])
            elif len(name_items) > 1:
                combined_items.append(SigmaDetection(detection_items=name_items, item_linking=ConditionOR))
            
            if len(value_items) == 1:
                combined_items.append(value_items[0])
            elif len(value_items) > 1:
                combined_items.append(SigmaDetection(detection_items=value_items, item_linking=ConditionOR))

            all_transformations.append(SigmaDetection(detection_items=combined_items, item_linking=ConditionAND))

        # For contains without backslash: combine ObjectName and OBJECTVALUENAME with OR
        contains_items = []
        if object_name_contains:
            contains_items.append(SigmaDetectionItem("ObjectName", [SigmaContainsModifier], value=object_name_contains))
        if object_value_contains:
            contains_items.append(SigmaDetectionItem("OBJECTVALUENAME", [SigmaContainsModifier], value=object_value_contains))
        
        if contains_items:
            if len(contains_items) == 1:
                all_transformations.append(contains_items[0])
            else:
                all_transformations.append(SigmaDetection(detection_items=contains_items, item_linking=ConditionOR))

        # Add compound contains transformations
        all_transformations.extend(compound_transformations)

        # Return final result
        if all_transformations:
            if len(all_transformations) == 1:
                return SigmaDetection(
                    detection_items=[detection_item, all_transformations[0]],
                    item_linking=ConditionOR,
                )
            else:
                combined_transformations = SigmaDetection(
                    detection_items=all_transformations,
                    item_linking=ConditionOR,
                )
                return SigmaDetection(
                    detection_items=[detection_item, combined_transformations],
                    item_linking=ConditionOR,
                )

        return detection_item


class DuplicateChangeTransformation(DetectionItemTransformation):
    """
    Transforms the 'Details' field from a compact representation to a more detailed structure.
    It also duplicates the original 'Details' field into an 'INFORMATION' field.

    Example:
        Input:
            Details: ['DWORD (0x00000001)', 'DWORD (0x00000002)']
        Output:
            (
                INFORMATN: ['DWORD (0x00000001)', 'DWORD (0x00000002)'] OR
                (CHANGES: [1, 2] AND NEWTYPE: ['REG_DWORD', 'REG_DWORD'])
            )
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> SigmaDetectionItem:
        if detection_item.field != "Details":
            return detection_item

        if not isinstance(detection_item.value, list):
            values = [detection_item.value]
        else:
            values = detection_item.value

        changes_values = []
        newtype_values = []
        informatn_values = []
        can_transform_all = True

        type_mapping = {
            "DWORD": "REG_DWORD",
            "BINARY": "REG_BINARY",
            "DWORD_LITTLE_ENDIAN": "REG_DWORD_LITTLE_ENDIAN",
            "DWORD_BIG_ENDIAN": "REG_DWORD_BIG_ENDIAN",
            "EXPAND_SZ": "REG_EXPAND_SZ",
            "LINK": "REG_LINK",
            "MULTI_SZ": "REG_MULTI_SZ",
            "NONE": "REG_NONE",
            "QWORD": "REG_QWORD",
            "QWORD_LITTLE_ENDIAN": "REG_QWORD_LITTLE_ENDIAN",
            "SZ": "REG_SZ",
        }

        for v in values:
            if not isinstance(v, SigmaString):
                can_transform_all = False
                break

            s_value = str(v)
            match = re.match(r"(\w+)\s+\((0x[0-9a-fA-F]+)\)", s_value)

            if not match:
                can_transform_all = False
                break

            reg_type, hex_value = match.groups()
            dec_value = int(hex_value, 16)
            new_type = type_mapping.get(reg_type.upper())

            if not new_type:
                can_transform_all = False
                break

            changes_values.append(SigmaNumber(dec_value))
            newtype_values.append(SigmaString(new_type))
            informatn_values.append(v)

        if not can_transform_all or not changes_values:
            return SigmaDetectionItem(
                "INFORMATN", detection_item.modifiers, value=detection_item.value
            )

        return SigmaDetection(
            detection_items=[
                SigmaDetectionItem(
                    "INFORMATN", detection_item.modifiers, value=informatn_values
                ),
                SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem("CHANGES", [], value=changes_values),
                        SigmaDetectionItem("NEWTYPE", [], value=newtype_values),
                    ],
                    item_linking=ConditionAND,
                ),
            ],
            item_linking=ConditionOR,
        )


class DuplicateTargetFilenameTransformation(DetectionItemTransformation):
    """
    Duplicates the TargetFilename field into an ObjectName field.
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> SigmaDetectionItem:
        if detection_item.field == "TargetFilename"  or detection_item.field == "FileName":
            return SigmaDetection(
                detection_items=[
                    detection_item,
                    SigmaDetectionItem(
                        "ObjectName",
                        detection_item.modifiers,
                        value=detection_item.value,
                    ),
                ],
                item_linking=ConditionOR,
            )
        return detection_item
