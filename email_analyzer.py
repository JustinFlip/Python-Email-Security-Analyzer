#!/usr/bin/env python3
import os
import email
import hashlib
import re
import requests
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
try:
    import PyPDF2
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
try:
    import docx
    DOCX_SUPPORT = True
except ImportError:
    DOCX_SUPPORT = False

# ========== CONFIG ==========
EMAIL_DIR = "emails"
ATTACHMENTS_DIR = "attachments"
VT_API_KEY = os.getenv("VT_API_KEY")  # optional
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls/"
# ============================

def sha256_hash(file_path):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Error hashing file {file_path}: {e}")
        return None

def check_virustotal_file(file_hash):
    """Check file hash against VirusTotal"""
    if not VT_API_KEY:
        print("[!] VirusTotal API key not set, skipping VT check")
        print("[!] Set VT_API_KEY environment variable to enable scanning")
        return
    
    if not file_hash:
        print("[!] Invalid file hash")
        return
    
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(VT_FILE_URL + file_hash, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total_scans = malicious + suspicious + undetected + stats.get("harmless", 0)
            
            print(f"\n[VT] VirusTotal Results:")
            print(f"  - Malicious: {malicious}")
            print(f"  - Suspicious: {suspicious}")
            print(f"  - Undetected: {undetected}")
            print(f"  - Total scans: {total_scans}")
            
            # Verdict
            if malicious > 0:
                print(f"  ⚠️  VERDICT: MALICIOUS ({malicious}/{total_scans} engines detected threats)")
            elif suspicious > 0:
                print(f"  ⚠️  VERDICT: SUSPICIOUS ({suspicious}/{total_scans} engines flagged as suspicious)")
            else:
                print(f"  ✓ VERDICT: CLEAN (No threats detected)")
            
        elif response.status_code == 404:
            print(f"[VT] File not found in VirusTotal database")
            print(f"[VT] This file hasn't been scanned before - consider uploading it manually")
        else:
            print(f"[VT] API error (Status: {response.status_code})")
    except Exception as e:
        print(f"[VT] Error checking VirusTotal: {e}")

def check_virustotal_url(url):
    """Check URL against VirusTotal"""
    if not VT_API_KEY:
        return None
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # First, encode the URL for VirusTotal
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Check if URL has been scanned before
        response = requests.get(VT_URL_SCAN + url_id, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total_scans = malicious + suspicious + harmless + undetected
            
            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total_scans,
                "scanned": True
            }
        else:
            # URL not in database
            return {"scanned": False}
    except Exception as e:
        print(f"    [VT Error] {e}")
        return None

def extract_urls(text):
    """Extract URLs from text"""
    if not text:
        return []
    return re.findall(r"https?://[^\s<>\"']+", text)

def extract_urls_from_file(filepath):
    """Extract URLs from various file types"""
    urls = []
    filename = os.path.basename(filepath).lower()
    
    try:
        # PDF files
        if filename.endswith('.pdf'):
            if not PDF_SUPPORT:
                print(f"[!] PyPDF2 not installed. Cannot extract URLs from PDF. Install with: pip install PyPDF2 --break-system-packages")
                return urls
            try:
                with open(filepath, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    for page in pdf_reader.pages:
                        text = page.extract_text()
                        urls.extend(extract_urls(text))
            except Exception as e:
                print(f"[!] Error reading PDF: {e}")
        
        # Word documents
        elif filename.endswith('.docx'):
            if not DOCX_SUPPORT:
                print(f"[!] python-docx not installed. Cannot extract URLs from DOCX. Install with: pip install python-docx --break-system-packages")
                return urls
            try:
                doc = docx.Document(filepath)
                for para in doc.paragraphs:
                    urls.extend(extract_urls(para.text))
            except Exception as e:
                print(f"[!] Error reading DOCX: {e}")
        
        # Text files, HTML, XML, etc.
        elif filename.endswith(('.txt', '.html', '.htm', '.xml', '.csv', '.log')):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    urls.extend(extract_urls(content))
            except Exception as e:
                print(f"[!] Error reading text file: {e}")
        
        # Try as text for other files
        else:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    urls.extend(extract_urls(content))
            except:
                # If it fails, it's probably a binary file we can't parse
                pass
    
    except Exception as e:
        print(f"[!] Error extracting URLs from {filepath}: {e}")
    
    return list(set(urls))  # Remove duplicates

def save_attachment(part, attachment_dir):
    """Save email attachment to disk"""
    filename = part.get_filename()
    if filename:
        # Sanitize filename
        filename = re.sub(r'[^\w\s.-]', '_', filename)
        filepath = os.path.join(attachment_dir, filename)
        
        # Handle duplicate filenames
        counter = 1
        base_name, ext = os.path.splitext(filepath)
        while os.path.exists(filepath):
            filepath = f"{base_name}_{counter}{ext}"
            counter += 1
        
        try:
            with open(filepath, "wb") as f:
                f.write(part.get_payload(decode=True))
            print(f"[+] Saved attachment: {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error saving attachment {filename}: {e}")
            return None
    return None

def analyze_email(eml_path):
    """Analyze an email file for security indicators"""
    print(f"\n{'='*60}")
    print(f"=== Analyzing: {eml_path} ===")
    print(f"{'='*60}")
    
    try:
        with open(eml_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        print(f"[!] Error parsing email: {e}")
        return
    
    # --- HEADERS ---
    print("\n[*] Email Headers:")
    print(f"From: {msg.get('From')}")
    print(f"To: {msg.get('To')}")
    print(f"Subject: {msg.get('Subject')}")
    print(f"Date: {msg.get('Date')}")
    
    # Check for spoofing indicators
    return_path = msg.get('Return-Path')
    if return_path:
        print(f"Return-Path: {return_path}")
    
    # --- BODY & LINKS ---
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body_text += part.get_content()
                except:
                    pass
            elif content_type == "text/html":
                try:
                    soup = BeautifulSoup(part.get_content(), "html.parser")
                    body_text += soup.get_text()
                except:
                    pass
    else:
        try:
            body_text = msg.get_content()
        except:
            body_text = ""
    
    # Extract and display URLs
    urls = extract_urls(body_text)
    if urls:
        print(f"\n[+] Found {len(urls)} URL(s) in email body:")
        for url in urls:
            print(f"  - {url}")
            
            # Check URL with VirusTotal
            if VT_API_KEY:
                result = check_virustotal_url(url)
                if result and result.get("scanned"):
                    malicious = result["malicious"]
                    suspicious = result["suspicious"]
                    total = result["total"]
                    
                    if malicious > 0:
                        print(f"    ⚠️  MALICIOUS: {malicious}/{total} engines flagged this URL")
                    elif suspicious > 0:
                        print(f"    ⚠️  SUSPICIOUS: {suspicious}/{total} engines flagged this URL")
                    else:
                        print(f"    ✓ CLEAN: No threats detected")
                elif result and not result.get("scanned"):
                    print(f"    [VT] URL not in database (not previously scanned)")
    else:
        print("\n[-] No URLs found")
    
    # --- ATTACHMENTS ---
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
    attachments_found = False
    all_attachment_urls = []
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                attachments_found = True
                filename = part.get_filename()
                print(f"\n[!] Attachment found: {filename}")
                
                # Save attachment
                filepath = save_attachment(part, ATTACHMENTS_DIR)
                
                # Calculate hash and check VirusTotal
                if filepath:
                    file_hash = sha256_hash(filepath)
                    if file_hash:
                        print(f"[*] SHA256: {file_hash}")
                        check_virustotal_file(file_hash)
                    
                    # Extract URLs from attachment
                    attachment_urls = extract_urls_from_file(filepath)
                    if attachment_urls:
                        print(f"[+] Found {len(attachment_urls)} URL(s) in attachment:")
                        for url in attachment_urls:
                            print(f"  - {url}")
                        all_attachment_urls.extend(attachment_urls)
                    else:
                        print("[-] No URLs found in attachment")
    
    if not attachments_found:
        print("\n[-] No attachments found")
    elif all_attachment_urls:
        print(f"\n[*] Total unique URLs from all attachments: {len(set(all_attachment_urls))}")

def main():
    """Main function to analyze all emails in the EMAIL_DIR"""
    if not os.path.exists(EMAIL_DIR):
        print(f"[!] Email directory '{EMAIL_DIR}' not found!")
        print(f"[*] Creating directory...")
        os.makedirs(EMAIL_DIR)
        print(f"[*] Place .eml files in '{EMAIL_DIR}' and run again")
        return
    
    # Get all .eml files
    eml_files = [f for f in os.listdir(EMAIL_DIR) if f.endswith('.eml')]
    
    if not eml_files:
        print(f"[!] No .eml files found in '{EMAIL_DIR}'")
        return
    
    print(f"[*] Found {len(eml_files)} email(s) to analyze")
    
    # Analyze each email
    for eml_file in eml_files:
        eml_path = os.path.join(EMAIL_DIR, eml_file)
        analyze_email(eml_path)
    
    print(f"\n{'='*60}")
    print("[*] Analysis complete!")
    print(f"{'='*60}")
    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║                                                          ║")
    print("  ║        ██╗██╗   ██╗███████╗████████╗██╗███╗   ██╗       ║")
    print("  ║        ██║██║   ██║██╔════╝╚══██╔══╝██║████╗  ██║       ║")
    print("  ║        ██║██║   ██║███████╗   ██║   ██║██╔██╗ ██║       ║")
    print("  ║   ██   ██║██║   ██║╚════██║   ██║   ██║██║╚██╗██║       ║")
    print("  ║   ╚█████╔╝╚██████╔╝███████║   ██║   ██║██║ ╚████║       ║")
    print("  ║    ╚════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝       ║")
    print("  ║                                                          ║")
    print("  ║         ███████╗██╗     ██╗██████╗                      ║")
    print("  ║         ██╔════╝██║     ██║██╔══██╗                     ║")
    print("  ║         █████╗  ██║     ██║██████╔╝                     ║")
    print("  ║         ██╔══╝  ██║     ██║██╔═══╝                      ║")
    print("  ║         ██║     ███████╗██║██║                          ║")
    print("  ║         ╚═╝     ╚══════╝╚═╝╚═╝                          ║")
    print("  ║                                                          ║")
    print("  ║              Email Security Analyzer v1.0                ║")
    print("  ║                                                          ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print()

if __name__ == "__main__":
    main()
