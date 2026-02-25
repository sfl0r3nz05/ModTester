#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ReportGenerator.py  -  System/Core/ReportGenerator.py
------------------------------------------------------
Generates a standardised ICS/OT security assessment .docx report from
ModTester Output/ files. Maps findings to CVSS v3.1, CWE, IEC 62443.

Zero external dependencies - uses Python 2/3 stdlib only (zipfile + xml).
No Node.js, no npm, no docx package required.

Usage (from ModTester module):
    from ReportGenerator import generate_report
    generate_report(target_ip, port, output_dir, assessor, organisation, report_path)

Usage (standalone):
    python System/Core/ReportGenerator.py --target 192.168.159.128 --port 5020
"""

from __future__ import print_function

import os
import re
import json
import zipfile
import io
from datetime import datetime

# ---------------------------------------------------------------------------
# Finding catalogue - triggers matched against Output filename (lowercase)
# ---------------------------------------------------------------------------
FINDING_CATALOGUE = [
    {
        "id"           : "F-01",
        "title"        : "Unauthenticated Modbus Service Accessible",
        "trigger"      : ["modbusdetect", "modbus discover", "discover"],
        "description"  : "The Modbus/TCP service on port {port} accepts connections and responds to function code requests without any form of authentication. Any host with TCP connectivity can issue arbitrary Modbus commands.",
        "impact"       : "An unauthenticated attacker can read process data, modify setpoints, and control physical actuators without credentials.",
        "cwe"          : "CWE-306",
        "cwe_name"     : "Missing Authentication for Critical Function",
        "cvss_vector"  : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",
        "cvss_score"   : 9.1,
        "cvss_rating"  : "Critical",
        "iec62443_sr"  : "SR 1.1",
        "iec62443_desc": "Human User Identification and Authentication",
        "remediation"  : "Deploy Modbus Security (MBAP+TLS, IEC 62351-3) or place the device behind a Modbus-aware industrial firewall. Implement network segmentation per ISA/IEC 62443 Zone and Conduit model.",
    },
    {
        "id"           : "F-02",
        "title"        : "Device Identity Exposed via FC43 (Read Device Identification)",
        "trigger"      : ["bannergrabbing", "banner_grabbing"],
        "description"  : "Function Code 43 (Read Device Identification) returns full vendor, product name, and firmware revision without authentication.",
        "impact"       : "Device identity (vendor, model, firmware) enables targeted exploit selection. Firmware version exposure may reveal known vulnerabilities.",
        "cwe"          : "CWE-200",
        "cwe_name"     : "Exposure of Sensitive Information to an Unauthorized Actor",
        "cvss_vector"  : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_score"   : 5.3,
        "cvss_rating"  : "Medium",
        "iec62443_sr"  : "SR 1.1 / SR 7.7",
        "iec62443_desc": "Identification and Authentication / Least Functionality",
        "remediation"  : "Disable FC43 where not operationally required. If unavoidable, restrict Modbus port access via firewall ACLs to authorised engineering workstations only.",
    },
    {
        "id"           : "F-03",
        "title"        : "All Unit IDs (1-254) Respond Without Filtering",
        "trigger"      : ["findunitid", "brute force uid", "uid"],
        "description"  : "The device responds to Modbus requests addressed to all Unit IDs in the range 1-254. No Unit ID allowlist is enforced.",
        "impact"       : "An attacker does not need to enumerate the correct Unit ID before issuing commands, eliminating a weak but intended access-segmentation mechanism.",
        "cwe"          : "CWE-284",
        "cwe_name"     : "Improper Access Control",
        "cvss_vector"  : "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cvss_score"   : 5.3,
        "cvss_rating"  : "Medium",
        "iec62443_sr"  : "SR 2.1",
        "iec62443_desc": "Authorization Enforcement",
        "remediation"  : "Configure the device or gateway to accept only the specific Unit ID(s) assigned during commissioning and reject all others.",
    },
    {
        "id"           : "F-04",
        "title"        : "Unauthenticated Read of All Process Data (FC01/02/03/04)",
        "trigger"      : ["coildiscover", "holdingregisterdiscover", "inputregisterdiscover",
                          "discreteinputdiscover", "coil discover", "holding register discover",
                          "input register discover", "discrete input",
                          "read_coils", "read_holding", "read_input", "read_discrete",
                          "get function"],
        "description"  : "Coil status (FC01), discrete inputs (FC02), holding registers (FC03), and input registers (FC04) are all readable without authentication, exposing the complete operational state of the device.",
        "impact"       : "An attacker gains full situational awareness of the process: motor speeds, valve positions, sensor readings, setpoints, and counters.",
        "cwe"          : "CWE-306",
        "cwe_name"     : "Missing Authentication for Critical Function",
        "cvss_vector"  : "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score"   : 7.5,
        "cvss_rating"  : "High",
        "iec62443_sr"  : "SR 2.1",
        "iec62443_desc": "Authorization Enforcement",
        "remediation"  : "Implement read-access controls at the network boundary using a Modbus-aware industrial firewall or data diode for read-only consumers.",
    },
    {
        "id"           : "F-05",
        "title"        : "Unauthenticated Write to Coils and Registers (FC05/06/15/16)",
        "trigger"      : ["writesingle", "write single", "write_coil",
                          "write_register", "write_coils", "write_registers"],
        "description"  : "Write function codes FC05, FC06, FC15, and FC16 are accepted without authentication. Any host with TCP access can arbitrarily modify process setpoints and actuator states.",
        "impact"       : "An attacker can shut down motors by zeroing coils, inject out-of-range setpoints (e.g. RPM 1500 to 9999), reset counters, or perform mass shutdown of all actuators with a single FC15 packet.",
        "cwe"          : "CWE-306",
        "cwe_name"     : "Missing Authentication for Critical Function",
        "cvss_vector"  : "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cvss_score"   : 9.1,
        "cvss_rating"  : "Critical",
        "iec62443_sr"  : "SR 2.1",
        "iec62443_desc": "Authorization Enforcement",
        "remediation"  : "Priority order: (1) Deploy Modbus Security/MBAP+TLS if supported. (2) Use a Modbus-aware firewall to whitelist specific function codes, address ranges, and source IPs. (3) Network segmentation as defence-in-depth.",
    },
    {
        "id"           : "F-06",
        "title"        : "No Rate Limiting - Susceptible to Denial of Service",
        "trigger"      : ["flooding", "floodingattack"],
        "description"  : "The Modbus/TCP service does not enforce connection rate limits or request throttling. A flooding attack saturates the service, causing legitimate SCADA/HMI systems to lose communication.",
        "impact"       : "Loss of visibility and control for operators. The controller may operate on last-known state or enter fail-safe mode, which may itself be unsafe depending on the process.",
        "cwe"          : "CWE-400",
        "cwe_name"     : "Uncontrolled Resource Consumption",
        "cvss_vector"  : "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss_score"   : 7.5,
        "cvss_rating"  : "High",
        "iec62443_sr"  : "SR 7.2",
        "iec62443_desc": "Resource Management",
        "remediation"  : "Enforce TCP connection limits and Modbus request rate limits at the network boundary via industrial firewall or switch ACL.",
    },
]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# ---------------------------------------------------------------------------
# Output directory scanning and finding matching
# ---------------------------------------------------------------------------

def _scan_output_dir(output_dir):
    found = []
    if not os.path.isdir(output_dir):
        return found
    for fname in os.listdir(output_dir):
        if fname.endswith('.txt'):
            found.append((fname.lower(), os.path.join(output_dir, fname)))
    return found


def _match_findings(output_files, target_ip, port):
    matched = []
    seen_ids = set()
    for fname_lower, fpath in output_files:
        for finding in FINDING_CATALOGUE:
            if finding["id"] in seen_ids:
                continue
            for trigger in finding["trigger"]:
                if trigger in fname_lower:
                    snippet = ""
                    try:
                        with open(fpath, 'r') as f:
                            raw = f.read(2000)
                        ansi_re = re.compile(r'\x1b\[[0-9;]*[mABCDEFGHJKSTfnsulhp]')
                        snippet = ansi_re.sub('', raw).strip()
                    except Exception:
                        snippet = "(unable to read evidence file)"
                    f_copy = dict(finding)
                    f_copy["description"] = finding["description"].replace("{port}", str(port))
                    f_copy["evidence_file"]    = fpath
                    f_copy["evidence_snippet"] = snippet[:600]
                    matched.append(f_copy)
                    seen_ids.add(finding["id"])
                    break
    matched.sort(key=lambda x: SEVERITY_ORDER.get(x["cvss_rating"], 99))
    return matched


# ---------------------------------------------------------------------------
# Pure Python .docx generation (stdlib zipfile only - no Node.js required)
# ---------------------------------------------------------------------------

def _esc(text):
    """XML-escape a plain text string."""
    if not isinstance(text, str):
        try:
            text = text.encode('ascii', 'replace').decode('ascii')
        except Exception:
            text = str(text)
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    return text


def _para(text, style=None, bold=False, size=None, colour=None, align=None):
    """Build a <w:p> XML element."""
    parts = ['<w:p>']
    pPr = []
    if style:
        pPr.append('<w:pStyle w:val="{}"/>'.format(style))
    if align:
        pPr.append('<w:jc w:val="{}"/>'.format(align))
    if pPr:
        parts.append('<w:pPr>' + ''.join(pPr) + '</w:pPr>')
    if text:
        rPr = []
        if bold:
            rPr.append('<w:b/>')
        if size:
            rPr.append('<w:sz w:val="{}"/>'.format(size))
            rPr.append('<w:szCs w:val="{}"/>'.format(size))
        if colour:
            rPr.append('<w:color w:val="{}"/>'.format(colour))
        rPr_xml = ('<w:rPr>' + ''.join(rPr) + '</w:rPr>') if rPr else ''
        # Split on newlines to preserve line breaks
        lines = _esc(text).split('\n')
        for i, line in enumerate(lines):
            parts.append('<w:r>{}<w:t xml:space="preserve">{}</w:t></w:r>'.format(rPr_xml, line))
            if i < len(lines) - 1:
                parts.append('<w:r><w:br/></w:r>')
    parts.append('</w:p>')
    return ''.join(parts)


def _table_row(cells, header=False, shade=None):
    """Build a <w:tr> element. cells = list of (text, width_dxa, opts_dict)."""
    parts = ['<w:tr>']
    if header:
        parts.append('<w:trPr><w:tblHeader/></w:trPr>')
    for text, width, opts in cells:
        opts = opts or {}
        parts.append('<w:tc>')
        parts.append('<w:tcPr>')
        parts.append('<w:tcW w:w="{}" w:type="dxa"/>'.format(width))
        fill = opts.get('fill', shade or 'FFFFFF')
        parts.append('<w:shd w:val="clear" w:color="auto" w:fill="{}"/>'.format(fill))
        parts.append('<w:tcMar><w:top w:w="80" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tcMar>')
        parts.append('</w:tcPr>')
        colour  = opts.get('colour', 'FFFFFF' if fill not in ('FFFFFF', 'D9E1F2', 'F2F2F2', 'EBF3FB') else '000000')
        bold    = opts.get('bold', header)
        size    = opts.get('size', 18)
        align   = opts.get('align', None)
        parts.append(_para(str(text), bold=bold, size=size, colour=colour, align=align))
        parts.append('</w:tc>')
    parts.append('</w:tr>')
    return ''.join(parts)


SEVERITY_COLOUR = {
    "Critical": "C00000",
    "High":     "E26B0A",
    "Medium":   "BF8F00",
    "Low":      "375623",
    "Info":     "1F4E79",
}

HDR_BLUE  = "1F4E79"
ALT_ROW   = "D9E1F2"
HDR_TEXT  = "FFFFFF"


def _build_document_xml(target_ip, port, findings, assessor, organisation, date_str, ts_str):
    NS = ('xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" '
          'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
          'xmlns:o="urn:schemas-microsoft-com:office:office" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
          'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" '
          'xmlns:v="urn:schemas-microsoft-com:vml" '
          'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
          'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
          'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
          'xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" '
          'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"')

    W = 9026  # A4 content width in DXA (1" margins)

    crit  = sum(1 for f in findings if f['cvss_rating'] == 'Critical')
    high  = sum(1 for f in findings if f['cvss_rating'] == 'High')
    med   = sum(1 for f in findings if f['cvss_rating'] == 'Medium')
    total = len(findings)

    body = []

    # ---- COVER PAGE --------------------------------------------------------
    body.append(_para('ICS / OT Security Assessment Report',
                      bold=True, size=52, colour=HDR_BLUE, align='center'))
    body.append(_para('Modbus Protocol Security Evaluation',
                      size=28, colour='444444', align='center'))
    body.append(_para('', size=20))
    body.append(_para('Target: {}:{}'.format(target_ip, port),
                      bold=True, size=28, colour=HDR_BLUE, align='center'))
    body.append(_para('Organisation: {}'.format(organisation), size=22, align='center'))
    body.append(_para('Assessor: {}'.format(assessor), size=22, align='center'))
    body.append(_para('Date: {}'.format(date_str), size=22, align='center'))
    body.append(_para('', size=20))

    # Summary boxes as a table
    qw = W // 4
    body.append('<w:tbl><w:tblPr><w:tblW w:w="{}" w:type="dxa"/></w:tblPr><w:tblGrid>{}</w:tblGrid>'.format(
        W, '<w:gridCol w:w="{}"/>'.format(qw) * 4))
    body.append(_table_row([
        ('{} CRITICAL'.format(crit), qw, {'fill': 'C00000', 'colour': 'FFFFFF', 'bold': True, 'size': 28}),
        ('{} HIGH'.format(high),     qw, {'fill': 'E26B0A', 'colour': 'FFFFFF', 'bold': True, 'size': 28}),
        ('{} MEDIUM'.format(med),    qw, {'fill': 'BF8F00', 'colour': 'FFFFFF', 'bold': True, 'size': 28}),
        ('{} TOTAL'.format(total),   qw, {'fill': '595959', 'colour': 'FFFFFF', 'bold': True, 'size': 28}),
    ]))
    body.append('</w:tbl>')

    # Page break
    body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    # ---- EXECUTIVE SUMMARY -------------------------------------------------
    body.append(_para('1. Executive Summary', style='Heading1'))
    body.append(_para(
        'This report presents the results of a Modbus protocol security assessment '
        'conducted against {}:{}. Testing was performed using ModTester '
        '(github.com/sfl0r3nz05/ModTester) integrated with Metasploit Framework '
        'SCADA auxiliary modules on {}.'.format(target_ip, port, date_str)))
    body.append(_para(
        'Modbus is a protocol designed in 1979 without authentication, encryption, '
        'or access control. The {} finding(s) documented here represent the inherent '
        'risk of operating this protocol in its default configuration on a TCP network. '
        '{} are rated Critical (CVSS >= 9.0), {} High, and {} Medium. No CVE identifiers '
        'are assigned as these are protocol-level design weaknesses; findings are mapped '
        'to CWE and IEC/ISA 62443 Security Requirements.'.format(total, crit, high, med)))

    # ---- SCOPE -------------------------------------------------------------
    body.append(_para('2. Assessment Scope', style='Heading1'))
    cw1, cw2 = 2800, W - 2800
    body.append('<w:tbl><w:tblPr><w:tblW w:w="{}" w:type="dxa"/></w:tblPr><w:tblGrid><w:gridCol w:w="{}"/><w:gridCol w:w="{}"/></w:tblGrid>'.format(W, cw1, cw2))
    body.append(_table_row([('Parameter', cw1, {'fill': HDR_BLUE, 'colour': HDR_TEXT}), ('Value', cw2, {'fill': HDR_BLUE, 'colour': HDR_TEXT})], header=True))
    scope_rows = [
        ('Target IP',       target_ip),
        ('Target Port',     '{} / TCP (Modbus/TCP)'.format(port)),
        ('Protocol',        'Modbus/TCP (MBAP framing)'),
        ('Assessment Date', date_str),
        ('Assessor',        assessor),
        ('Organisation',    organisation),
        ('Tool',            'ModTester v1.1 + Metasploit Framework 6.4'),
    ]
    for i, (k, v) in enumerate(scope_rows):
        shade = ALT_ROW if i % 2 == 0 else 'FFFFFF'
        body.append(_table_row([(k, cw1, {'fill': shade}), (v, cw2, {'fill': shade})]))
    body.append('</w:tbl>')

    # ---- FINDINGS SUMMARY --------------------------------------------------
    body.append(_para('', size=20))
    body.append(_para('3. Findings Summary', style='Heading1'))
    col_w = [500, 4226, 1000, 1000, 1300]
    body.append('<w:tbl><w:tblPr><w:tblW w:w="{}" w:type="dxa"/></w:tblPr><w:tblGrid>{}</w:tblGrid>'.format(
        W, ''.join('<w:gridCol w:w="{}"/>'.format(c) for c in col_w)))
    body.append(_table_row([
        ('ID',       col_w[0], {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
        ('Title',    col_w[1], {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
        ('CVSS',     col_w[2], {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
        ('Severity', col_w[3], {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
        ('IEC 62443',col_w[4], {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
    ], header=True))
    for i, f in enumerate(findings):
        shade = ALT_ROW if i % 2 == 0 else 'FFFFFF'
        sc    = SEVERITY_COLOUR.get(f['cvss_rating'], '888888')
        body.append(_table_row([
            (f['id'],           col_w[0], {'fill': shade}),
            (f['title'],        col_w[1], {'fill': shade}),
            (str(f['cvss_score']), col_w[2], {'fill': shade, 'colour': sc, 'bold': True}),
            (f['cvss_rating'],  col_w[3], {'fill': sc, 'colour': 'FFFFFF', 'bold': True}),
            (f['iec62443_sr'],  col_w[4], {'fill': shade}),
        ]))
    body.append('</w:tbl>')

    body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    # ---- DETAILED FINDINGS -------------------------------------------------
    body.append(_para('4. Detailed Findings', style='Heading1'))

    for f in findings:
        sc = SEVERITY_COLOUR.get(f['cvss_rating'], '888888')
        body.append(_para('{} - {}'.format(f['id'], f['title']), style='Heading2'))

        # References table
        rw = W // 4
        body.append('<w:tbl><w:tblPr><w:tblW w:w="{}" w:type="dxa"/></w:tblPr><w:tblGrid>{}</w:tblGrid>'.format(
            W, '<w:gridCol w:w="{}"/>'.format(rw) * 4))
        body.append(_table_row([
            ('CVSS v3.1',  rw, {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
            ('CWE',        rw, {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
            ('IEC 62443',  rw, {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
            ('Vector',     rw, {'fill': HDR_BLUE, 'colour': HDR_TEXT}),
        ], header=True))
        body.append(_table_row([
            ('{} ({})'.format(f['cvss_score'], f['cvss_rating']), rw, {'fill': sc, 'colour': 'FFFFFF', 'bold': True, 'size': 22}),
            ('{}\n{}'.format(f['cwe'], f['cwe_name']), rw, {}),
            ('{}\n{}'.format(f['iec62443_sr'], f['iec62443_desc']), rw, {}),
            (f['cvss_vector'], rw, {'size': 16}),
        ]))
        body.append('</w:tbl>')

        body.append(_para('Description', bold=True))
        body.append(_para(f['description']))
        body.append(_para('Impact', bold=True))
        body.append(_para(f['impact']))
        body.append(_para('Remediation', bold=True))
        body.append(_para(f['remediation']))

        # Evidence
        body.append(_para('Evidence', bold=True))
        snippet = f.get('evidence_snippet', '').strip()
        if snippet:
            # Evidence in a shaded box
            body.append('<w:tbl><w:tblPr><w:tblW w:w="{}" w:type="dxa"/></w:tblPr><w:tblGrid><w:gridCol w:w="{}"/></w:tblGrid>'.format(W, W))
            body.append('<w:tr><w:tc><w:tcPr><w:tcW w:w="{}" w:type="dxa"/><w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/><w:tcMar><w:top w:w="80" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tcMar></w:tcPr>'.format(W))
            lines = _esc(snippet).split('\n')
            for line in lines[:20]:
                body.append('<w:p><w:pPr><w:pStyle w:val="Code"/></w:pPr><w:r><w:rPr><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr><w:t xml:space="preserve">{}</w:t></w:r></w:p>'.format(line))
            body.append('</w:tc></w:tr></w:tbl>')
        body.append(_para('', size=20))

    # ---- APPENDIX ----------------------------------------------------------
    body.append(_para('5. Methodology', style='Heading1'))
    for phase in [
        'Phase 1 - Discovery: modbusdetect, portDiscover, discover',
        'Phase 2 - Fingerprinting: modbus_banner_grabbing (FC43)',
        'Phase 3 - Enumeration: modbus_findunitid, uid (UID brute-force), getfunc',
        'Phase 4 - Register Read: coilDiscover, holdingRegisterDiscover, inputRegisterDiscover',
        'Phase 5 - Write Exploitation: writeSingleCoils, writeSingleRegister, modbusclient (FC05/06/15/16)',
        'Phase 6 - Denial of Service: floodingAttack',
    ]:
        body.append(_para(phase))

    body.append(_para('6. References', style='Heading1'))
    for ref in [
        'Modbus Application Protocol Specification v1.1b3 - modbus.org',
        'IEC 62443-3-3:2013 - System security requirements and security levels',
        'MITRE CWE - https://cwe.mitre.org',
        'CVSS v3.1 Specification - https://www.first.org/cvss/v3.1/specification-document',
        'ModTester - https://github.com/sfl0r3nz05/ModTester',
        'Metasploit SCADA Modules - https://github.com/rapid7/metasploit-framework',
    ]:
        body.append(_para(ref))

    body.append(_para('Generated by ModTester ReportGenerator on {}'.format(ts_str),
                      size=16, colour='888888'))

    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document {ns}>'
        '<w:body>'
        '{body}'
        '<w:sectPr>'
        '<w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/>'
        '</w:sectPr>'
        '</w:body>'
        '</w:document>'
    ).format(ns=NS, body=''.join(body))

    return doc_xml


def _build_styles_xml():
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault><w:rPr>
      <w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial"/>
      <w:sz w:val="20"/><w:szCs w:val="20"/>
    </w:rPr></w:rPrDefault>
  </w:docDefaults>
  <w:style w:type="paragraph" w:styleId="Normal">
    <w:name w:val="Normal"/>
    <w:pPr><w:spacing w:after="120"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial"/><w:sz w:val="20"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>
    <w:pPr><w:spacing w:before="320" w:after="160"/><w:outlineLvl w:val="0"/></w:pPr>
    <w:rPr><w:b/><w:color w:val="1F4E79"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>
    <w:pPr><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="1"/></w:pPr>
    <w:rPr><w:b/><w:color w:val="2E4057"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Code">
    <w:name w:val="Code"/><w:basedOn w:val="Normal"/>
    <w:pPr><w:spacing w:after="0"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" w:cs="Courier New"/><w:sz w:val="16"/></w:rPr>
  </w:style>
</w:styles>'''


def _write_docx_pure(target_ip, port, findings, assessor, organisation, out_path):
    """Write the .docx using stdlib zipfile only. No Node.js required."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    ts_str   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    doc_xml    = _build_document_xml(target_ip, port, findings, assessor, organisation, date_str, ts_str)
    styles_xml = _build_styles_xml()

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml"  ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml"   ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '</Relationships>'
    )
    word_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        '</Relationships>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', content_types.encode('utf-8'))
        zf.writestr('_rels/.rels',                rels.encode('utf-8'))
        zf.writestr('word/_rels/document.xml.rels', word_rels.encode('utf-8'))
        zf.writestr('word/document.xml',           doc_xml.encode('utf-8'))
        zf.writestr('word/styles.xml',             styles_xml.encode('utf-8'))

    with open(out_path, 'wb') as f:
        f.write(buf.getvalue())

    return out_path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(target_ip, port, output_dir, assessor="ModTester",
                    organisation="Target Organisation", report_path=None):
    if report_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(
            output_dir,
            "ModTester_Report_{}_{}.docx".format(target_ip, ts)
        )

    output_files = _scan_output_dir(output_dir)
    findings     = _match_findings(output_files, target_ip, port)

    print("[Report] {} finding(s) matched from {} output file(s).".format(
        len(findings), len(output_files)))

    try:
        _write_docx_pure(target_ip, port, findings, assessor, organisation, report_path)
        print("[Report] Generated: {}".format(report_path))
        return report_path
    except Exception as e:
        print("[Report] ERROR: {}".format(e))
        import traceback
        traceback.print_exc()
        return None


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    def _get(args, flag, default):
        if flag in args:
            i = args.index(flag)
            if i + 1 < len(args):
                return args[i + 1]
        return default

    args = sys.argv[1:]
    if not args or "--help" in args:
        print("Usage: python ReportGenerator.py --target <ip> [--port <port>]")
        print("         [--assessor <name>] [--org <org>] [--outdir <dir>] [--output <file>]")
        sys.exit(0)

    _HERE      = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = os.path.abspath(os.path.join(_HERE, '..', '..', 'Output'))

    target_ip    = _get(args, "--target",   "127.0.0.1")
    port         = int(_get(args, "--port", "502"))
    assessor     = _get(args, "--assessor", "ModTester")
    organisation = _get(args, "--org",      "Target Organisation")
    output_dir   = _get(args, "--outdir",   OUTPUT_DIR)
    report_path  = _get(args, "--output",   None)

    path = generate_report(target_ip, port, output_dir, assessor, organisation, report_path)
    if path:
        print("Report saved: {}".format(path))
    else:
        sys.exit(1)