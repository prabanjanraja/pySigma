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

        if not detection_item.value or not isinstance(detection_item.value[0], SigmaString):
            return detection_item

        s_value = str(detection_item.value[0])
        modifiers = detection_item.modifiers

        transformed_detection = None

        # Equals (no modifier)
        if not modifiers:
            if "\\" in s_value:
                object_name, object_value = s_value.rsplit("\\", 1)
                transformed_detection = SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem("ObjectName", [], value=[SigmaString(object_name)]),
                        SigmaDetectionItem("OBJECTVALUENAME", [], value=[SigmaString(object_value)]),
                    ],
                    item_linking=ConditionAND,
                )

        # StartsWith
        elif SigmaStartswithModifier in modifiers:
            if "\\" in s_value:
                name_part, value_part = s_value.rsplit("\\", 1)
                transformed_detection = SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem("ObjectName", [], value=[SigmaString(name_part)]),
                        SigmaDetectionItem(
                            "OBJECTVALUENAME",
                            [SigmaStartswithModifier],
                            value=[SigmaString(value_part)],
                        ),
                    ],
                    item_linking=ConditionAND,
                )
            else:
                transformed_detection = SigmaDetectionItem(
                    "ObjectName", [SigmaStartswithModifier], value=[SigmaString(s_value)]
                )

        # EndsWith
        elif SigmaEndswithModifier in modifiers:
            if "\\" in s_value:
                name_part, value_part = s_value.rsplit("\\", 1)
                if name_part:
                    transformed_detection = SigmaDetection(
                        detection_items=[
                            SigmaDetectionItem(
                                "ObjectName", [SigmaEndswithModifier], value=[SigmaString(name_part)]
                            ),
                            SigmaDetectionItem("OBJECTVALUENAME", [], value=[SigmaString(value_part)]),
                        ],
                        item_linking=ConditionAND,
                    )
                else:
                    transformed_detection = SigmaDetection(
                        detection_items=[
                            SigmaDetectionItem("OBJECTVALUENAME", [], value=[SigmaString(value_part)]),
                        ],
                        item_linking=ConditionAND,
                    )
            else:
                transformed_detection = SigmaDetectionItem(
                    "OBJECTVALUENAME", [SigmaEndswithModifier], value=[SigmaString(s_value)]
                )

        # Contains
        elif SigmaContainsModifier in modifiers:
            if "\\" in s_value:
                name_part, value_part = s_value.rsplit("\\", 1)
                # ObjectName|contains: 'foo\bar' OR (ObjectName|endswith: 'foo' AND OBJECTVALUENAME|startswith: 'bar')
                transformed_detection = SigmaDetection(
                    detection_items=[
                                SigmaDetectionItem(
                                    "ObjectName",
                                    [SigmaEndswithModifier],
                                    value=[SigmaString(name_part)],
                                ),
                                SigmaDetectionItem(
                                    "OBJECTVALUENAME",
                                    [SigmaStartswithModifier],
                                    value=[SigmaString(value_part)],
                                ),
                            ],
                            item_linking=ConditionAND,
                )
            else:
                # ObjectName|contains: 'value' OR OBJECTVALUENAME|contains: 'value'
                transformed_detection = SigmaDetection(
                    detection_items=[
                        SigmaDetectionItem(
                            "ObjectName", [SigmaContainsModifier], value=[SigmaString(s_value)]
                        ),
                        SigmaDetectionItem(
                            "OBJECTVALUENAME", [SigmaContainsModifier], value=[SigmaString(s_value)]
                        ),
                    ],
                    item_linking=ConditionOR,
                )

        if transformed_detection:
            return SigmaDetection(
                detection_items=[
                    detection_item,
                    transformed_detection,
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
