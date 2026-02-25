#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ReportGenerator.py  -  System/Core/ReportGenerator.py
------------------------------------------------------
Reads ModTester Output/ files and generates a standardized ICS/OT
security assessment report.

Standardization layers applied per finding (no CVE required):
  - CVSS v3.1  : Attack Vector / Complexity / Privileges / Impact
  - CWE        : Common Weakness Enumeration mapping
  - IEC 62443  : Security Requirement (SR) reference
  - PTES       : Penetration Testing Execution Standard section

Usage (standalone):
  python System/Core/ReportGenerator.py \
      --target 192.168.159.128 \
      --port 5020 \
      --assessor "Your Name" \
      --org "Client Organisation" \
      --output report.docx

Usage (from ModTester module):
  from ReportGenerator import generate_report
  generate_report(target_ip, port, findings_list, output_path)
"""

from __future__ import print_function

import os
import re
import json
import subprocess
import tempfile
from datetime import datetime

# ---------------------------------------------------------------------------
# Finding catalogue
# Each entry maps a module/condition to standard references.
# 'trigger' is matched against Output file names (lowercase).
# ---------------------------------------------------------------------------

FINDING_CATALOGUE = [
    {
        "id"          : "F-01",
        "title"       : "Unauthenticated Modbus Service Accessible",
        "trigger"     : ["modbusdetect", "modbus discover", "discover"],
        "description" : (
            "The Modbus/TCP service is accessible from the network without "
            "any form of authentication. Any host with TCP connectivity to "
            "port {port} can issue arbitrary Modbus commands."
        ),
        "impact"      : (
            "An unauthenticated attacker can read process data, modify "
            "setpoints, and control physical actuators without any credentials."
        ),
        "cwe"         : "CWE-306",
        "cwe_name"    : "Missing Authentication for Critical Function",
        "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",
        "cvss_score"  : 9.1,
        "cvss_rating" : "Critical",
        "iec62443_sr" : "SR 1.1",
        "iec62443_desc": "Human User Identification and Authentication",
        "remediation" : (
            "Deploy Modbus Security (MBAP+TLS, IEC 62351-3) or place the "
            "device behind a next-generation firewall with application-layer "
            "Modbus inspection. Implement network segmentation (ISA/IEC 62443 "
            "Zone & Conduit model) so the device is not directly reachable "
            "from untrusted segments."
        ),
    },
    {
        "id"          : "F-02",
        "title"       : "Device Identity Exposed via FC43 (Read Device Identification)",
        "trigger"     : ["bannergrabbing", "banner_grabbing"],
        "description" : (
            "Function Code 43 (Read Device Identification, MEI Type 0x0E) is "
            "supported and returns full vendor, product, and firmware version "
            "information without authentication."
        ),
        "impact"      : (
            "Detailed device identity (vendor, model, firmware revision) "
            "enables targeted exploit selection and supply-chain attack "
            "planning. Firmware version exposure may reveal known "
            "vulnerabilities applicable to the specific revision."
        ),
        "cwe"         : "CWE-200",
        "cwe_name"    : "Exposure of Sensitive Information to an Unauthorized Actor",
        "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_score"  : 5.3,
        "cvss_rating" : "Medium",
        "iec62443_sr" : "SR 1.1 / SR 7.7",
        "iec62443_desc": "Human User Identification and Authentication / Least Functionality",
        "remediation" : (
            "Disable FC43 support where not operationally required. If the "
            "device does not allow disabling FC43, restrict access to the "
            "Modbus port via firewall ACLs to authorised engineering "
            "workstations only."
        ),
    },
    {
        "id"          : "F-03",
        "title"       : "All Unit IDs (1-254) Respond Without Filtering",
        "trigger"     : ["findunitid", "modbusuidscane", "brute force uid", "uid"],
        "description" : (
            "The device responds to Modbus requests addressed to all Unit IDs "
            "in the range 1-254. No Unit ID allowlist is enforced."
        ),
        "impact"      : (
            "Unit ID filtering is a weak but intended access-segmentation "
            "mechanism for multi-drop serial networks bridged to TCP. Its "
            "absence means an attacker does not need to enumerate the correct "
            "Unit ID before issuing commands."
        ),
        "cwe"         : "CWE-284",
        "cwe_name"    : "Improper Access Control",
        "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cvss_score"  : 5.3,
        "cvss_rating" : "Medium",
        "iec62443_sr" : "SR 2.1",
        "iec62443_desc": "Authorization Enforcement",
        "remediation" : (
            "Configure the device or gateway to accept only the specific "
            "Unit ID(s) assigned during commissioning and return exception "
            "code 0x04 (Server Failure) or silently drop requests addressed "
            "to other Unit IDs."
        ),
    },
    {
        "id"          : "F-04",
        "title"       : "Unauthenticated Read of All Process Data (FC01/02/03/04)",
        "trigger"     : ["coildiscover", "holdingregisterdiscover",
                         "inputregisterdiscover", "discreteinputdiscover",
                         "coil discover", "holding register discover",
                         "input register discover", "discrete input",
                         "read_coils", "read_holding", "read_input",
                         "read_discrete"],
        "description" : (
            "Coil status (FC01), discrete inputs (FC02), holding registers "
            "(FC03), and input registers (FC04) are all readable without "
            "authentication, exposing the complete operational state of "
            "the device."
        ),
        "impact"      : (
            "An attacker gains full situational awareness of the process: "
            "motor speeds, valve positions, sensor readings, setpoints, and "
            "counters. This information enables targeted manipulation attacks "
            "and supports reconnaissance for physical process interference."
        ),
        "cwe"         : "CWE-306",
        "cwe_name"    : "Missing Authentication for Critical Function",
        "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score"  : 7.5,
        "cvss_rating" : "High",
        "iec62443_sr" : "SR 2.1",
        "iec62443_desc": "Authorization Enforcement",
        "remediation" : (
            "Implement read-access controls at the network boundary using a "
            "Modbus-aware industrial firewall or data diode for read-only "
            "consumers (SCADA, historians). Apply IEC 62443 Zone & Conduit "
            "architecture to limit which hosts may query the device."
        ),
    },
    {
        "id"          : "F-05",
        "title"       : "Unauthenticated Write to Coils and Registers (FC05/06/15/16)",
        "trigger"     : ["writesingle", "write single", "write_coil",
                         "write_register", "write_coils", "write_registers",
                         "get function"],
        "description" : (
            "Write function codes FC05 (Write Single Coil), FC06 (Write "
            "Single Register), FC15 (Write Multiple Coils), and FC16 (Write "
            "Multiple Registers) are accepted without authentication. Any "
            "host with TCP access can arbitrarily modify process setpoints "
            "and actuator states."
        ),
        "impact"      : (
            "An attacker can: shut down motors and pumps by zeroing coils; "
            "inject out-of-range setpoints (e.g. motor RPM: 1500 -> 9999) "
            "that may cause physical damage or process upset; reset counters "
            "and timers; and perform mass shutdown of all actuators with a "
            "single FC15 packet. This is the highest-impact Modbus attack "
            "class and is exploitable by a low-skilled attacker with a "
            "single off-the-shelf packet."
        ),
        "cwe"         : "CWE-306",
        "cwe_name"    : "Missing Authentication for Critical Function",
        "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cvss_score"  : 9.1,
        "cvss_rating" : "Critical",
        "iec62443_sr" : "SR 2.1",
        "iec62443_desc": "Authorization Enforcement",
        "remediation" : (
            "This is the fundamental Modbus protocol limitation. Mitigations "
            "in priority order: (1) Deploy Modbus Security / MBAP+TLS "
            "(IEC 62351-3) if the device supports it. (2) Use a Modbus-aware "
            "industrial firewall to whitelist only the specific function codes, "
            "address ranges, and source IPs needed for normal operation. "
            "(3) Implement OPC-UA with security profiles as a replacement "
            "protocol for new deployments. (4) Network segmentation as a "
            "defence-in-depth measure."
        ),
    },
    {
        "id"          : "F-06",
        "title"       : "No Rate Limiting — Susceptible to Denial of Service (Flooding)",
        "trigger"     : ["flooding", "floodingattack"],
        "description" : (
            "The Modbus/TCP service does not enforce connection rate limits "
            "or request throttling. A flooding attack saturates the service, "
            "causing legitimate SCADA/HMI systems to lose communication."
        ),
        "impact"      : (
            "Loss of visibility and control for operators. In a process where "
            "the PLC/RTU relies on SCADA polling for supervisory setpoints, "
            "a sustained flood causes the controller to operate on its last "
            "known state or enter a fail-safe mode, which may itself be "
            "unsafe depending on the process."
        ),
        "cwe"         : "CWE-400",
        "cwe_name"    : "Uncontrolled Resource Consumption",
        "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss_score"  : 7.5,
        "cvss_rating" : "High",
        "iec62443_sr" : "SR 7.2",
        "iec62443_desc": "Resource Management",
        "remediation" : (
            "Enforce TCP connection limits and Modbus request rate limits at "
            "the network boundary (industrial firewall or switch ACL). "
            "Consider dedicated Modbus-to-secure-protocol gateways that "
            "absorb floods before they reach the field device."
        ),
    },
]

# ---------------------------------------------------------------------------
# CVSS colour mapping (used in the docx report)
# ---------------------------------------------------------------------------
SEVERITY_COLOURS = {
    "Critical" : "C00000",  # dark red
    "High"     : "E26B0A",  # orange
    "Medium"   : "F0D000",  # yellow
    "Low"      : "70AD47",  # green
    "Info"     : "4472C4",  # blue
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan_output_dir(output_dir):
    """Return list of (filename_lower, full_path) for all .txt files in Output/."""
    found = []
    if not os.path.isdir(output_dir):
        return found
    for fname in os.listdir(output_dir):
        if fname.endswith('.txt'):
            found.append((fname.lower(), os.path.join(output_dir, fname)))
    return found


def _match_findings(output_files, target_ip, port):
    """
    Match output files against FINDING_CATALOGUE triggers.
    Returns list of finding dicts, each enriched with:
      - evidence_file : path to the output file that triggered it
      - evidence_snippet : first 20 relevant lines from the file
    """
    matched = []
    seen_ids = set()

    for fname_lower, fpath in output_files:
        for finding in FINDING_CATALOGUE:
            if finding["id"] in seen_ids:
                continue
            for trigger in finding["trigger"]:
                if trigger in fname_lower:
                    # Read evidence snippet
                    snippet = ""
                    try:
                        with open(fpath, 'r') as f:
                            lines = [l.rstrip() for l in f.readlines()]
                            # Strip ANSI from evidence
                            ansi_re = re.compile(r'\x1b\[[0-9;]*[mABCDEFGHJKSTfnsulhp]')
                            clean = [ansi_re.sub('', l) for l in lines]
                            snippet = "\n".join(clean[:30])
                    except Exception:
                        snippet = "(unable to read evidence file)"

                    f_copy = dict(finding)
                    f_copy["description"] = finding["description"].format(port=port)
                    f_copy["evidence_file"]    = fpath
                    f_copy["evidence_snippet"] = snippet
                    matched.append(f_copy)
                    seen_ids.add(finding["id"])
                    break

    # Sort by CVSS score descending
    matched.sort(key=lambda x: x["cvss_score"], reverse=True)
    return matched


def generate_report(target_ip, port, output_dir, assessor="ModTester",
                    organisation="Target Organisation",
                    report_path=None):
    """
    Main entry point. Scans output_dir, matches findings, writes .docx report.
    Returns path to the generated report.
    """
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

    _write_docx(target_ip, port, findings, assessor, organisation, report_path)
    return report_path


def _write_docx(target_ip, port, findings, assessor, organisation, out_path):
    """Generate the .docx report using docx-js via Node.js subprocess."""

    # Serialise findings to JSON for the JS script
    findings_json = json.dumps(findings, ensure_ascii=True)
    date_str      = datetime.now().strftime("%Y-%m-%d")
    ts_str        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    js_script = r"""
'use strict';
const fs   = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  VerticalAlign, PageNumber, PageBreak, LevelFormat, Header, Footer,
  TabStopType, TabStopPosition
} = require('docx');

// -- Data injected from Python ------------------------------------------------
const TARGET_IP    = """ + json.dumps(target_ip) + r""";
const TARGET_PORT  = """ + json.dumps(str(port)) + r""";
const ASSESSOR     = """ + json.dumps(assessor) + r""";
const ORGANISATION = """ + json.dumps(organisation) + r""";
const DATE_STR     = """ + json.dumps(date_str) + r""";
const TS_STR       = """ + json.dumps(ts_str) + r""";
const FINDINGS     = """ + findings_json + r""";
const OUT_PATH     = """ + json.dumps(out_path) + r""";

// -- Colours ------------------------------------------------------------------
const COLOURS = {
  Critical : 'C00000',
  High     : 'E26B0A',
  Medium   : 'BF8F00',
  Low      : '375623',
  Info     : '1F4E79',
  header   : '1F4E79',
  hdrText  : 'FFFFFF',
  altRow   : 'D9E1F2',
  border   : 'B8CCE4',
};

// -- Helpers ------------------------------------------------------------------
const W = 9360; // content width DXA (A4, 1" margins)

function cellBorder(colour) {
  const b = { style: BorderStyle.SINGLE, size: 1, color: colour };
  return { top: b, bottom: b, left: b, right: b };
}

function hdrCell(text, widthDxa) {
  return new TableCell({
    width: { size: widthDxa, type: WidthType.DXA },
    borders: cellBorder(COLOURS.border),
    shading: { fill: COLOURS.header, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: [new Paragraph({
      children: [new TextRun({ text, bold: true, color: COLOURS.hdrText, size: 18, font: 'Arial' })]
    })]
  });
}

function dataCell(text, widthDxa, opts) {
  opts = opts || {};
  return new TableCell({
    width: { size: widthDxa, type: WidthType.DXA },
    borders: cellBorder(COLOURS.border),
    shading: opts.fill ? { fill: opts.fill, type: ShadingType.CLEAR } : undefined,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    verticalAlign: opts.vAlign || VerticalAlign.TOP,
    children: [new Paragraph({
      children: [new TextRun({
        text: String(text),
        bold: !!opts.bold,
        color: opts.color || '000000',
        size: opts.size || 18,
        font: 'Arial',
      })]
    })]
  });
}

function para(text, opts) {
  opts = opts || {};
  return new Paragraph({
    heading: opts.heading,
    spacing: { before: opts.spaceBefore || 120, after: opts.spaceAfter || 120 },
    children: [new TextRun({
      text,
      bold: !!opts.bold,
      size: opts.size || 20,
      font: 'Arial',
      color: opts.color || '000000',
      italics: !!opts.italics,
    })]
  });
}

function sectionHeading(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 320, after: 160 },
    children: [new TextRun({ text, bold: true, size: 28, font: 'Arial', color: COLOURS.header })]
  });
}

function subHeading(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 100 },
    children: [new TextRun({ text, bold: true, size: 22, font: 'Arial', color: '2E4057' })]
  });
}

function hr() {
  return new Paragraph({
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLOURS.border, space: 1 } },
    spacing: { before: 0, after: 160 },
    children: []
  });
}

function labelValue(label, value) {
  return new Paragraph({
    spacing: { before: 60, after: 60 },
    children: [
      new TextRun({ text: label + ': ', bold: true, size: 18, font: 'Arial' }),
      new TextRun({ text: String(value), size: 18, font: 'Arial' }),
    ]
  });
}

function severityBadge(rating) {
  const colour = COLOURS[rating] || '888888';
  return new TableCell({
    width: { size: 1400, type: WidthType.DXA },
    borders: cellBorder(COLOURS.border),
    shading: { fill: colour, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: rating.toUpperCase(), bold: true, color: 'FFFFFF', size: 18, font: 'Arial' })]
    })]
  });
}

// -- Summary table ---------------------------------------------------------
function buildSummaryTable(findings) {
  const colW = [500, 4560, 1400, 1400, 1500];
  const hdrRow = new TableRow({
    tableHeader: true,
    children: [
      hdrCell('ID',       colW[0]),
      hdrCell('Title',    colW[1]),
      hdrCell('CVSS',     colW[2]),
      hdrCell('Severity', colW[3]),
      hdrCell('IEC 62443',colW[4]),
    ]
  });

  const rows = findings.map((f, i) => {
    const fill = i % 2 === 1 ? COLOURS.altRow : 'FFFFFF';
    const sc   = COLOURS[f.cvss_rating] || '888888';
    return new TableRow({
      children: [
        dataCell(f.id,           colW[0], { fill }),
        dataCell(f.title,        colW[1], { fill }),
        new TableCell({
          width: { size: colW[2], type: WidthType.DXA },
          borders: cellBorder(COLOURS.border),
          shading: { fill, type: ShadingType.CLEAR },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({
            children: [new TextRun({ text: String(f.cvss_score), bold: true, color: sc, size: 18, font: 'Arial' })]
          })]
        }),
        new TableCell({
          width: { size: colW[3], type: WidthType.DXA },
          borders: cellBorder(COLOURS.border),
          shading: { fill: sc, type: ShadingType.CLEAR },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: f.cvss_rating.toUpperCase(), bold: true, color: 'FFFFFF', size: 16, font: 'Arial' })]
          })]
        }),
        dataCell(f.iec62443_sr,  colW[4], { fill }),
      ]
    });
  });

  return new Table({
    width: { size: W, type: WidthType.DXA },
    columnWidths: colW,
    rows: [hdrRow, ...rows],
  });
}

// -- Individual finding block ----------------------------------------------
function buildFindingBlock(f) {
  const sc = COLOURS[f.cvss_rating] || '888888';

  // References table
  const refColW = [2200, 2200, 2200, 2760];
  const refTable = new Table({
    width: { size: W, type: WidthType.DXA },
    columnWidths: refColW,
    rows: [
      new TableRow({
        tableHeader: true,
        children: [
          hdrCell('CVSS v3.1 Score', refColW[0]),
          hdrCell('CWE', refColW[1]),
          hdrCell('IEC 62443 SR', refColW[2]),
          hdrCell('CVSS Vector', refColW[3]),
        ]
      }),
      new TableRow({
        children: [
          new TableCell({
            width: { size: refColW[0], type: WidthType.DXA },
            borders: cellBorder(COLOURS.border),
            shading: { fill: sc, type: ShadingType.CLEAR },
            margins: { top: 80, bottom: 80, left: 120, right: 120 },
            children: [new Paragraph({
              alignment: AlignmentType.CENTER,
              children: [new TextRun({ text: String(f.cvss_score) + ' ' + f.cvss_rating, bold: true, color: 'FFFFFF', size: 22, font: 'Arial' })]
            })]
          }),
          dataCell(f.cwe + '\n' + f.cwe_name, refColW[1], {}),
          dataCell(f.iec62443_sr + '\n' + f.iec62443_desc, refColW[2], {}),
          dataCell(f.cvss_vector, refColW[3], { size: 16 }),
        ]
      })
    ]
  });

  // Evidence snippet table
  const evidenceTable = new Table({
    width: { size: W, type: WidthType.DXA },
    columnWidths: [W],
    rows: [
      new TableRow({
        tableHeader: true,
        children: [hdrCell('Evidence (ModTester Output)', W)]
      }),
      new TableRow({
        children: [new TableCell({
          width: { size: W, type: WidthType.DXA },
          borders: cellBorder(COLOURS.border),
          shading: { fill: 'F2F2F2', type: ShadingType.CLEAR },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({
            children: [new TextRun({
              text: (f.evidence_snippet || '').substring(0, 800),
              size: 16, font: 'Courier New', color: '333333'
            })]
          })]
        })]
      })
    ]
  });

  return [
    subHeading(f.id + '  ' + f.title),
    para('Description', { bold: true }),
    para(f.description),
    para('Impact', { bold: true }),
    para(f.impact),
    refTable,
    new Paragraph({ spacing: { before: 120, after: 120 }, children: [] }),
    para('Remediation', { bold: true }),
    para(f.remediation),
    new Paragraph({ spacing: { before: 80, after: 80 }, children: [] }),
    evidenceTable,
    new Paragraph({ spacing: { before: 200, after: 200 }, children: [] }),
    hr(),
  ];
}

// -- Cover page -----------------------------------------------------------
function buildCoverPage(findings) {
  const critCount = findings.filter(f => f.cvss_rating === 'Critical').length;
  const highCount = findings.filter(f => f.cvss_rating === 'High').length;
  const medCount  = findings.filter(f => f.cvss_rating === 'Medium').length;

  return [
    new Paragraph({ spacing: { before: 2000, after: 400 }, children: [
      new TextRun({ text: 'ICS / OT Security Assessment Report', bold: true, size: 52, font: 'Arial', color: COLOURS.header })
    ], alignment: AlignmentType.CENTER }),
    new Paragraph({ spacing: { before: 0, after: 200 }, alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'Modbus Protocol Security Evaluation', size: 28, font: 'Arial', color: '444444' })]
    }),
    hr(),
    new Paragraph({ spacing: { before: 400, after: 100 }, alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'Target Device', bold: true, size: 22, font: 'Arial' })]
    }),
    new Paragraph({ spacing: { before: 0, after: 80 }, alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: TARGET_IP + ':' + TARGET_PORT, size: 24, font: 'Courier New', color: COLOURS.header })]
    }),
    new Paragraph({ spacing: { before: 240, after: 80 }, alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'Organisation:  ' + ORGANISATION, size: 22, font: 'Arial' })]
    }),
    new Paragraph({ spacing: { before: 60, after: 80 }, alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'Assessor:  ' + ASSESSOR, size: 22, font: 'Arial' })]
    }),
    new Paragraph({ spacing: { before: 60, after: 400 }, alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'Date:  ' + DATE_STR, size: 22, font: 'Arial' })]
    }),
    hr(),
    // Findings summary boxes
    new Paragraph({ spacing: { before: 400, after: 200 }, alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'FINDINGS SUMMARY', bold: true, size: 24, font: 'Arial', color: COLOURS.header })]
    }),
    new Table({
      width: { size: W, type: WidthType.DXA },
      columnWidths: [W/4, W/4, W/4, W/4],
      rows: [
        new TableRow({ children: [
          new TableCell({
            width: { size: W/4, type: WidthType.DXA },
            borders: cellBorder(COLOURS.border),
            shading: { fill: COLOURS.Critical, type: ShadingType.CLEAR },
            margins: { top: 160, bottom: 160, left: 120, right: 120 },
            children: [
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(critCount), bold: true, size: 52, color: 'FFFFFF', font: 'Arial' })] }),
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'CRITICAL', bold: true, size: 20, color: 'FFFFFF', font: 'Arial' })] }),
            ]
          }),
          new TableCell({
            width: { size: W/4, type: WidthType.DXA },
            borders: cellBorder(COLOURS.border),
            shading: { fill: COLOURS.High, type: ShadingType.CLEAR },
            margins: { top: 160, bottom: 160, left: 120, right: 120 },
            children: [
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(highCount), bold: true, size: 52, color: 'FFFFFF', font: 'Arial' })] }),
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'HIGH', bold: true, size: 20, color: 'FFFFFF', font: 'Arial' })] }),
            ]
          }),
          new TableCell({
            width: { size: W/4, type: WidthType.DXA },
            borders: cellBorder(COLOURS.border),
            shading: { fill: COLOURS.Medium, type: ShadingType.CLEAR },
            margins: { top: 160, bottom: 160, left: 120, right: 120 },
            children: [
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(medCount), bold: true, size: 52, color: 'FFFFFF', font: 'Arial' })] }),
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'MEDIUM', bold: true, size: 20, color: 'FFFFFF', font: 'Arial' })] }),
            ]
          }),
          new TableCell({
            width: { size: W/4, type: WidthType.DXA },
            borders: cellBorder(COLOURS.border),
            shading: { fill: '888888', type: ShadingType.CLEAR },
            margins: { top: 160, bottom: 160, left: 120, right: 120 },
            children: [
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(findings.length), bold: true, size: 52, color: 'FFFFFF', font: 'Arial' })] }),
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'TOTAL', bold: true, size: 20, color: 'FFFFFF', font: 'Arial' })] }),
            ]
          }),
        ]})
      ]
    }),
    new Paragraph({ spacing: { before: 800, after: 0 }, children: [new PageBreak()] }),
  ];
}

// -- Main doc assembly -----------------------------------------------------
const coverChildren   = buildCoverPage(FINDINGS);
const summaryChildren = [
  sectionHeading('1. Executive Summary'),
  para(
    'This report presents the results of a Modbus protocol security assessment ' +
    'conducted against the device at ' + TARGET_IP + ':' + TARGET_PORT + '. ' +
    'The assessment was performed using ModTester (github.com/sfl0r3nz05/ModTester) ' +
    'integrated with Metasploit Framework SCADA auxiliary modules. ' +
    'All testing was conducted in a controlled environment on ' + DATE_STR + '.'
  ),
  para(
    'Modbus is a protocol designed in 1979 without authentication, encryption, ' +
    'or access control. The findings in this report are therefore expected for ' +
    'any standard Modbus implementation and represent the inherent risk of ' +
    'operating this protocol in its default configuration on a TCP network. ' +
    'They are documented here to support risk-based remediation decisions.'
  ),
  para(
    FINDINGS.length + ' findings were identified. ' +
    FINDINGS.filter(f => f.cvss_rating === 'Critical').length + ' are rated Critical (CVSS >= 9.0), ' +
    FINDINGS.filter(f => f.cvss_rating === 'High').length + ' are rated High, and ' +
    FINDINGS.filter(f => f.cvss_rating === 'Medium').length + ' are rated Medium. ' +
    'No CVE identifiers are assigned as these are protocol-level design weaknesses; ' +
    'findings are mapped to CWE and IEC/ISA 62443 Security Requirements instead.'
  ),
  new Paragraph({ spacing: { before: 200, after: 200 }, children: [] }),
  sectionHeading('2. Assessment Scope'),
  new Table({
    width: { size: W, type: WidthType.DXA },
    columnWidths: [2800, 6560],
    rows: [
      new TableRow({ children: [ hdrCell('Parameter', 2800), hdrCell('Value', 6560) ] }),
      new TableRow({ children: [ dataCell('Target IP', 2800, { fill: COLOURS.altRow }), dataCell(TARGET_IP, 6560, { fill: COLOURS.altRow }) ] }),
      new TableRow({ children: [ dataCell('Target Port', 2800), dataCell(TARGET_PORT + ' / TCP (Modbus/TCP)', 6560) ] }),
      new TableRow({ children: [ dataCell('Protocol', 2800, { fill: COLOURS.altRow }), dataCell('Modbus/TCP (MBAP framing)', 6560, { fill: COLOURS.altRow }) ] }),
      new TableRow({ children: [ dataCell('Assessment Date', 2800), dataCell(DATE_STR, 6560) ] }),
      new TableRow({ children: [ dataCell('Assessor', 2800, { fill: COLOURS.altRow }), dataCell(ASSESSOR, 6560, { fill: COLOURS.altRow }) ] }),
      new TableRow({ children: [ dataCell('Tool', 2800), dataCell('ModTester v1.1 + Metasploit Framework 6.4', 6560) ] }),
      new TableRow({ children: [ dataCell('Organisation', 2800, { fill: COLOURS.altRow }), dataCell(ORGANISATION, 6560, { fill: COLOURS.altRow }) ] }),
    ]
  }),
  new Paragraph({ spacing: { before: 200, after: 200 }, children: [] }),
  sectionHeading('3. Standardization Framework'),
  para('Findings are scored and referenced using the following standards, enabling comparison with existing vulnerability databases and compliance frameworks without requiring CVE assignment:'),
  para('CVSS v3.1: Base Score computed from Attack Vector, Complexity, Privileges Required, User Interaction, Scope, and CIA Impact. Scores range 0.0-10.0 (Critical >= 9.0, High >= 7.0, Medium >= 4.0).', { italics: false }),
  para('CWE (Common Weakness Enumeration): Classifies the underlying software/design weakness (e.g. CWE-306 Missing Authentication). Maintained by MITRE.'),
  para('IEC/ISA 62443: The OT security standard. Security Requirements (SR) referenced here define the security capability that the device fails to meet at Security Level 1.'),
  new Paragraph({ spacing: { before: 200, after: 200 }, children: [] }),
  sectionHeading('4. Findings Summary'),
  buildSummaryTable(FINDINGS),
  new Paragraph({ spacing: { before: 200, after: 0 }, children: [new PageBreak()] }),
];

const findingChildren = [
  sectionHeading('5. Detailed Findings'),
  ...FINDINGS.flatMap(f => buildFindingBlock(f)),
];

const appendixChildren = [
  sectionHeading('6. Methodology'),
  para('Phase 1 — Discovery: modbusdetect, portDiscover, discover'),
  para('Phase 2 — Fingerprinting: modbus_banner_grabbing (FC43)'),
  para('Phase 3 — Enumeration: modbus_findunitid, uid (UID brute-force)'),
  para('Phase 4 — Register Read: coilDiscover, discreteInputDiscover, holdingRegisterDiscover, inputRegisterDiscover, getfunc'),
  para('Phase 5 — Write Exploitation: writeSingleCoils, writeSingleRegister, writeSingleCoilsID, writeSingleRegisterID, modbusclient (FC05/06/15/16)'),
  para('Phase 6 — Denial of Service: floodingAttack'),
  new Paragraph({ spacing: { before: 240, after: 120 }, children: [] }),
  sectionHeading('7. References'),
  para('Modbus Application Protocol Specification v1.1b3 — modbus.org'),
  para('IEC 62443-3-3:2013 — System security requirements and security levels'),
  para('MITRE CWE — https://cwe.mitre.org'),
  para('CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document'),
  para('CISA ICS Advisories — https://www.cisa.gov/ics-advisories'),
  para('Pymodbus — https://github.com/pymodbus-dev/pymodbus'),
  para('ModTester — https://github.com/sfl0r3nz05/ModTester'),
  para('Metasploit SCADA Modules — https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner/scada'),
  para('Generated by ModTester ReportGenerator — ' + TS_STR, { italics: true, size: 16, color: '888888' }),
];

const doc = new Document({
  styles: {
    default: { document: { run: { font: 'Arial', size: 20 } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 28, bold: true, font: 'Arial', color: '1F4E79' },
        paragraph: { spacing: { before: 320, after: 160 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 22, bold: true, font: 'Arial', color: '2E4057' },
        paragraph: { spacing: { before: 240, after: 100 }, outlineLevel: 1 } },
    ]
  },
  sections: [{
    properties: {
      page: {
        size: { width: 11906, height: 16838 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
      }
    },
    children: [
      ...coverChildren,
      ...summaryChildren,
      ...findingChildren,
      ...appendixChildren,
    ]
  }]
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(OUT_PATH, buf);
  console.log('REPORT_OK:' + OUT_PATH);
}).catch(err => {
  console.error('REPORT_ERR:' + err.message);
  process.exit(1);
});
"""

    # Write JS to temp file and run it
    fd, js_path = tempfile.mkstemp(suffix=".js", prefix="modtester_report_")
    try:
        with os.fdopen(fd, "wb") as f:
            # Encode to bytes for Python 2/3 compatibility
            if isinstance(js_script, type(u'')):
                f.write(js_script.encode('utf-8'))
            else:
                f.write(js_script.encode('utf-8') if hasattr(js_script, 'encode') else js_script)

        # Resolve global npm root so require('docx') works from a /tmp script
        try:
            npm_root_proc = subprocess.Popen(
                ["npm", "root", "-g"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            npm_root = npm_root_proc.communicate()[0].decode("utf-8", errors="replace").strip()
        except OSError:
            npm_root = ""

        node_env = os.environ.copy()
        if npm_root:
            existing = node_env.get("NODE_PATH", "")
            node_env["NODE_PATH"] = (npm_root + os.pathsep + existing).rstrip(os.pathsep)

        result = subprocess.Popen(
            ["node", js_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=node_env,
        )
        stdout, stderr = result.communicate()
        stdout = stdout.decode("utf-8", errors="replace")
        stderr = stderr.decode("utf-8", errors="replace")
    finally:
        try:
            os.unlink(js_path)
        except Exception:
            pass

    # Always surface Node output so failures are visible
    if stderr.strip():
        print("[Report] Node stderr: {}".format(stderr.strip()))
    if stdout.strip() and "REPORT_OK:" not in stdout:
        print("[Report] Node stdout: {}".format(stdout.strip()))

    if "REPORT_OK:" in stdout:
        path = stdout.split("REPORT_OK:")[1].strip()
        print("[Report] Generated: {}".format(path))
        return path
    else:
        print("[Report] ERROR: docx not generated.")
        if not stderr.strip() and not stdout.strip():
            print("[Report] Node produced no output - check 'node' and 'npm' are on PATH.")
            print("[Report] Test with: node -e \"require('docx'); console.log('OK')\"")
        return None


# ===========================================================================
# CLI entry point
# ===========================================================================

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
        print("Usage: python ReportGenerator.py --target <ip> --port <port>")
        print("         [--assessor <name>] [--org <organisation>]")
        print("         [--outdir <output_dir>] [--output <report.docx>]")
        sys.exit(0)

    _HERE      = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = os.path.abspath(os.path.join(_HERE, '..', '..', 'Output'))

    target_ip    = _get(args, "--target",   "127.0.0.1")
    port         = int(_get(args, "--port", "502"))
    assessor     = _get(args, "--assessor", "ModTester")
    organisation = _get(args, "--org",      "Target Organisation")
    output_dir   = _get(args, "--outdir",   OUTPUT_DIR)
    report_path  = _get(args, "--output",   None)

    path = generate_report(target_ip, port, output_dir, assessor,
                           organisation, report_path)
    if path:
        print("Report saved: {}".format(path))
    else:
        sys.exit(1)