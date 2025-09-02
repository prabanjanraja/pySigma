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

    REGISTRY_PATH_MAPPING = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "\\REGISTRY\\MACHINE": "HKLM",
        "HKEY_USERS": "HKU",
        "\\REGISTRY\\USER": "HKU",
        "HKEY_CLASSES_ROOT": "HKCR",
        "HKEY_CURRENT_USER": "HKCU",
    }

    def _normalize_registry_path(self, path: str) -> str:
        for key, value in self.REGISTRY_PATH_MAPPING.items():
            path = path.replace(key, value)
        return path

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
            s_value = self._normalize_registry_path(str(sigma_string))

            # Improved splitting logic
            if s_value.endswith("\\(Default)"):
                name_part, value_part = s_value[:-10], "(Default)"
            elif "\\" in s_value:
                name_part, value_part = s_value.rsplit("\\", 1)
            else:
                name_part, value_part = s_value, None

            # Equals (no modifier)
            if not modifiers:
                if name_part and value_part:
                    object_names.append(SigmaString(name_part))
                    object_values.append(SigmaString(value_part))

            # StartsWith
            elif SigmaStartswithModifier in modifiers:
                if name_part and value_part:
                    object_names.append(SigmaString(name_part))
                    object_value_startswith.append(SigmaString(value_part))
                else:
                    object_name_startswith.append(SigmaString(name_part))

            # EndsWith
            elif SigmaEndswithModifier in modifiers:
                if name_part:
                    object_name_endswith.append(SigmaString(name_part))

            # Contains
            elif SigmaContainsModifier in modifiers:
                if name_part and value_part:
                    compound_contains.append(
                        (SigmaString(name_part), SigmaString(value_part))
                    )
                else:
                    object_name_contains.append(SigmaString(name_part))

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
            # Original detection with HOSTTYPE: Sysmon
            original_detection = SigmaDetection(
                detection_items=[
                    detection_item,
                    SigmaDetectionItem("HOSTTYPE", [], value=[SigmaString("Sysmon")]),
                ],
                item_linking=ConditionAND,
            )

            # New field with HOSTTYPE: windows
            new_field_detection = SigmaDetection(
                detection_items=[
                    SigmaDetection(
                        detection_items=all_transformations,
                        item_linking=ConditionOR,
                    ),
                    SigmaDetectionItem("HOSTTYPE", [], value=[SigmaString("windows")]),
                ],
                item_linking=ConditionAND,
            )

            return SigmaDetection(
                detection_items=[
                    original_detection,
                    new_field_detection,
                ],
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
                INFORMATION: ['DWORD (0x00000001)', 'DWORD (0x00000002)'] OR
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
        INFORMATION_values = []
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
            INFORMATION_values.append(v)

        if not can_transform_all or not changes_values:
            # Original detection with HOSTTYPE: Sysmon
            original_detection = SigmaDetection(
                detection_items=[
                    SigmaDetectionItem(
                        "INFORMATION", detection_item.modifiers, value=detection_item.value
                    ),
                    SigmaDetectionItem("HOSTTYPE", [], value=[SigmaString("Sysmon")]),
                ],
                item_linking=ConditionAND,
            )
            return original_detection

        # Original field with HOSTTYPE: Sysmon
        original_field_detection = SigmaDetection(
            detection_items=[
                SigmaDetectionItem(
                    "INFORMATION", detection_item.modifiers, value=INFORMATION_values
                ),
                SigmaDetectionItem("HOSTTYPE", [], value=[SigmaString("Sysmon")]),
            ],
            item_linking=ConditionAND,
        )

        # New field with HOSTTYPE: windows
        new_field_detection = SigmaDetection(
            detection_items=[
                SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem("CHANGES", [], value=changes_values),
                        SigmaDetectionItem("NEWTYPE", [], value=newtype_values),
                    ],
                    item_linking=ConditionAND,
                ),
                SigmaDetectionItem("HOSTTYPE", [], value=[SigmaString("windows")]),
            ],
            item_linking=ConditionAND,
        )

        return SigmaDetection(
            detection_items=[
                original_field_detection,
                new_field_detection,
            ],
            item_linking=ConditionOR,
        )


class DuplicateTargetFilenameTransformation(DetectionItemTransformation):
    """
    Duplicates the TargetFilename field into an ObjectName field.
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> SigmaDetectionItem:
        if detection_item.field == "TargetFilename" or detection_item.field == "FileName":
            # Original detection with HOSTTYPE: Sysmon
            original_detection = SigmaDetection(
                detection_items=[
                    detection_item,
                    SigmaDetectionItem("HOSTTYPE", [], value=[SigmaString("Sysmon")]),
                ],
                item_linking=ConditionAND,
            )

            # New field with HOSTTYPE: windows
            new_field_detection = SigmaDetection(
                detection_items=[
                    SigmaDetectionItem(
                        "ObjectName",
                        detection_item.modifiers,
                        value=detection_item.value,
                    ),
                    SigmaDetectionItem("HOSTTYPE", [], value=[SigmaString("windows")]),
                ],
                item_linking=ConditionAND,
            )

            return SigmaDetection(
                detection_items=[
                    original_detection,
                    new_field_detection,
                ],
                item_linking=ConditionOR,
            )
        return detection_item
