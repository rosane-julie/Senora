import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple
import asn1tools

TYPE_MAP = {
    'string': 'OCTET STRING',
    'octetstring': 'OCTET STRING',
    'integer': 'INTEGER',
    'int': 'INTEGER',
    'boolean': 'BOOLEAN',
    'bool': 'BOOLEAN'
}


def parse_xml(xml_bytes: bytes) -> List[Dict[str, str]]:
    """Parse XML decoder and return field definitions."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f'Invalid XML: {exc}') from exc

    fields = []
    for field in root.findall('.//field'):
        name = field.get('name')
        tag = field.get('tag') or field.get('id')
        ftype = field.get('type', 'string')
        if not name or tag is None:
            continue
        fields.append({'name': name, 'tag': tag, 'type': ftype})

    if not fields:
        raise ValueError('No fields found in XML')
    return fields


def build_asn1_spec(fields: List[Dict[str, str]]) -> str:
    """Build an ASN.1 specification from parsed fields."""
    lines = ['CDR DEFINITIONS ::= BEGIN', 'CDR ::= SEQUENCE {']
    for idx, f in enumerate(fields):
        asn1_type = TYPE_MAP.get(f['type'].lower(), 'OCTET STRING')
        comma = ',' if idx < len(fields) - 1 else ''
        lines.append(f"  {f['name']} [{f['tag']}] {asn1_type}{comma}")
    lines.append('}')
    lines.append('END')
    return '\n'.join(lines)


def compile_spec(xml_bytes: bytes) -> Tuple[asn1tools.compiler.AbstractCompiler, str]:
    """Parse Huawei style XML and compile a temporary ASN.1 module."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    fields = []

    # Huawei decoder definitions usually group fields under <record> elements.
    records = root.findall('.//record') or [root]
    for rec in records:
        for field in rec.findall('.//field'):
            name = field.get('name') or field.get('fieldName')
            tag = field.get('tag') or field.get('id')
            ftype = field.get('type') or field.get('dataType') or 'OCTET STRING'
            length = field.get('length') or field.get('len') or field.get('size')
            if name is None or tag is None:
                continue
            try:
                tag = int(tag, 0)
            except ValueError:
                continue
            fields.append({'name': name, 'tag': tag, 'type': ftype, 'length': length})

    if not fields:
        raise ValueError("No fields parsed from XML")

    print(f"Parsed {len(fields)} fields: {[f['name'] for f in fields]}")

    lines = ["MyCDR DEFINITIONS ::= BEGIN", "Record ::= SEQUENCE {"]
    for idx, f in enumerate(fields):
        asn1_type = TYPE_MAP.get(f['type'].lower(), f['type'].upper())
        constraint = ''
        if f['length']:
            ln = f['length'].replace(' ', '')
            if '..' in ln:
                constraint = f"(SIZE({ln}))" if asn1_type == 'OCTET STRING' else f"({ln})"
            else:
                constraint = f"(SIZE({ln}))" if asn1_type == 'OCTET STRING' else f"({ln})"
        line = f"    {f['name']} [{f['tag']}] {asn1_type}"
        if constraint:
            line += f" {constraint}"
        if idx < len(fields) - 1:
            line += ','
        lines.append(line)
    lines.append('}')
    lines.append('END')

    spec = '\n'.join(lines)
    compiler = asn1tools.compile_string(spec, 'ber')
    return compiler, spec


def decode_ber(xml_bytes: bytes, ber_bytes: bytes) -> Tuple[Dict, str]:
    """Decode BER data using XML decoder."""
    compiler, spec = compile_spec(xml_bytes)
    decoded = compiler.decode('CDR', ber_bytes)
    return decoded, spec


def encode_ber(spec: str, data: Dict) -> bytes:
    """Encode data dictionary into BER using provided ASN.1 spec."""
    compiler = asn1tools.compile_string(spec, 'ber')
    return compiler.encode('CDR', data)
