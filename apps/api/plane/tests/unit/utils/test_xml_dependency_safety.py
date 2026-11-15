# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

import importlib.util
import io

from defusedxml.common import DefusedXmlException
import openpyxl
from openpyxl.xml import functions
import pytest


pytestmark = pytest.mark.unit


def test_spreadsheet_parser_uses_explicit_entity_protection_without_libxml2():
    assert importlib.util.find_spec("lxml") is None
    assert openpyxl.LXML is False
    assert openpyxl.DEFUSEDXML is True
    assert functions.fromstring.__module__ == "defusedxml.common"
    assert functions.fromstring(b"<root><value>normal</value></root>").findtext("value") == "normal"


@pytest.mark.parametrize(
    "entity",
    ['"synthetic-content"', 'SYSTEM "file:///nonexistent-private-fixture"', 'SYSTEM "http://127.0.0.1:9/fixture"'],
)
def test_spreadsheet_parser_rejects_entity_expansion_and_external_resolution(entity):
    payload = f"<!DOCTYPE root [<!ENTITY fixture {entity}>]><root>&fixture;</root>".encode()
    with pytest.raises(DefusedXmlException):
        functions.fromstring(payload)


def test_spreadsheet_export_roundtrip_retains_unicode_formula_text_and_basic_formatting():
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet["A1"] = "Καλημέρα 世界"
    sheet["A2"] = "'=synthetic-formula-text"
    sheet["A1"].font = openpyxl.styles.Font(bold=True, color="FF0000")
    output = io.BytesIO()
    workbook.save(output)
    output.seek(0)
    loaded = openpyxl.load_workbook(output)
    assert loaded.active["A1"].value == "Καλημέρα 世界"
    assert loaded.active["A1"].font.bold is True
    assert loaded.active["A2"].value == "'=synthetic-formula-text"


@pytest.mark.parametrize("value", ["\r1+2", "line\r\nnext", "\r", "literal &#13; & < >", "世界\rΚαλημέρα"])
def test_export_writer_preserves_carriage_returns_and_xml_characters(value):
    from plane.utils.xlsx import save_xlsx

    workbook = openpyxl.Workbook()
    workbook.active["A1"] = value
    workbook.properties.creator = "author\rname"
    output = io.BytesIO()
    save_xlsx(workbook, output)
    output.seek(0)
    loaded = openpyxl.load_workbook(output)
    assert loaded.active["A1"].value == value
    assert loaded.properties.creator == "author\rname"


def test_export_writer_streams_large_worksheets_without_losing_unicode_or_cr():
    from plane.utils.xlsx import save_xlsx

    values = [("世界" + "text" * 1999 + "\r\nrow" + str(i)) for i in range(30)]
    workbook = openpyxl.Workbook()
    for value in values:
        workbook.active.append([value])
    output = io.BytesIO()
    save_xlsx(workbook, output)
    output.seek(0)
    loaded = openpyxl.load_workbook(output)
    assert [row[0] for row in loaded.active.values] == values
