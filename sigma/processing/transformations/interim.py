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
        values = detection_item.value if isinstance(detection_item.value, list) else [detection_item.value]

        # Filter for SigmaString values only
        string_values = [v for v in values if isinstance(v, SigmaString)]
        if not string_values:
            return detection_item

        transformed_detections = []
        for sigma_string in string_values:
            s_value = self._normalize_registry_path(str(sigma_string))

            # Determine transformation based on modifiers
            if not detection_item.modifiers:
                transformed_detections.append(self._handle_equals(s_value))
            elif SigmaStartswithModifier in detection_item.modifiers:
                transformed_detections.append(self._handle_startswith(s_value))
            elif SigmaEndswithModifier in detection_item.modifiers:
                transformed_detections.append(self._handle_endswith(s_value))
            elif SigmaContainsModifier in detection_item.modifiers:
                transformed_detections.append(self._handle_contains(s_value))

        if not transformed_detections:
            return detection_item

        # Combine all transformations with OR
        if len(transformed_detections) == 1:
            final_detection = transformed_detections[0]
        else:
            final_detection = SigmaDetection(detection_items=transformed_detections, item_linking=ConditionOR)

        return SigmaDetection(
            detection_items=[detection_item, final_detection],
            item_linking=ConditionOR,
        )

    def _split_value(self, value: str) -> tuple[str, str | None]:
        if value.endswith("\\(Default)"):
            return value[:-10], "(Default)"
        if "\\" in value:
            name_part, value_part = value.rsplit("\\", 1)
            return name_part, value_part
        return value, None

    def _handle_equals(self, value: str):
        name_part, value_part = self._split_value(value)
        if value_part:
            return SigmaDetection(
                detection_items=[
                    SigmaDetectionItem("ObjectName", [], value=[SigmaString(name_part)]),
                    SigmaDetectionItem("OBJECTVALUENAME", [], value=[SigmaString(value_part)]),
                ],
                item_linking=ConditionAND,
            )
        return SigmaDetectionItem("ObjectName", [], value=[SigmaString(name_part)])

    def _handle_startswith(self, value: str):
        return SigmaDetectionItem("ObjectName", [SigmaStartswithModifier], value=[SigmaString(value)])

    def _handle_endswith(self, value: str):
        name_part, value_part = self._split_value(value)
        if value_part:
            return SigmaDetection(
                detection_items=[
                    SigmaDetectionItem("ObjectName", [SigmaEndswithModifier], value=[SigmaString(name_part)]),
                    SigmaDetectionItem("OBJECTVALUENAME", [], value=[SigmaString(value_part)]),
                ],
                item_linking=ConditionAND,
            )
        return SigmaDetectionItem("ObjectName", [SigmaEndswithModifier], value=[SigmaString(name_part)])

    def _handle_contains(self, value: str):
        name_part, value_part = self._split_value(value)
        
        contains_object_name = SigmaDetectionItem("ObjectName", [SigmaContainsModifier], value=[SigmaString(value)])
        
        if value_part:
            # Case where the value spans the key and value name
            spanning_condition = SigmaDetection(
                detection_items=[
                    SigmaDetectionItem("ObjectName", [SigmaEndswithModifier], value=[SigmaString(name_part)]),
                    SigmaDetectionItem("OBJECTVALUENAME", [SigmaStartswithModifier], value=[SigmaString(value_part)]),
                ],
                item_linking=ConditionAND,
            )
            return SigmaDetection(
                detection_items=[contains_object_name, spanning_condition],
                item_linking=ConditionOR,
            )

        return contains_object_name


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
            return SigmaDetectionItem(
                "INFORMATION", detection_item.modifiers, value=detection_item.value
            )

        return SigmaDetection(
            detection_items=[
                SigmaDetectionItem(
                    "INFORMATION", detection_item.modifiers, value=INFORMATION_values
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
