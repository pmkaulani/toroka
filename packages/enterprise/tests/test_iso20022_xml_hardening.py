import pytest
from toroka_enterprise.integrations import iso20022

BOMB = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<Document><FIToFICstmrCdtTrf><x>&b;&b;&b;</x></FIToFICstmrCdtTrf></Document>"""

XXE = """<?xml version="1.0"?>
<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<Document><FIToFICstmrCdtTrf>&x;</FIToFICstmrCdtTrf></Document>"""


def _parser():
    for name in dir(iso20022):
        obj = getattr(iso20022, name)
        if hasattr(obj, "parse_pacs008_xml"):
            return obj.parse_pacs008_xml
    raise AssertionError("parse_pacs008_xml owner not found")


@pytest.mark.parametrize("payload", [BOMB, XXE])
def test_entity_declarations_are_rejected(payload):
    with pytest.raises(ValueError, match="unsafe|Malformed"):
        _parser()(payload)
