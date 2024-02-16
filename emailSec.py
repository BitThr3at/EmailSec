import dns.resolver
import json
import sys
import tldextract
from colorama import Fore, Style

def extract_root_domain(domain):
    extracted = tldextract.extract(domain)
    return "{}.{}".format(extracted.domain, extracted.suffix)

def check_spf_record(domain):
    results = {}
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for record in answers:
            if record.strings[0].startswith(b"v=spf1"):
                spf_record = record.strings[0].decode('utf-8')
                results['SPF Syntax Correct'] = "PASS" if "v=spf1" in spf_record else "FAIL"
                results['Strict SPF Filtering'] = "PASS" if "+all" not in spf_record else "FAIL: SPF uses +all"
                results['SPF ptr Mechanism Not Used'] = "PASS" if "ptr" not in spf_record else "FAIL: SPF uses ptr mechanism"
                return results
        results['SPF Record Found'] = "FAIL: No SPF record found"
    except Exception as e:
        results['SPF Record Check Error'] = f"FAIL: {e}"
    return results

def check_dmarc_record(domain):
    results = {}
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for record in answers:
            if record.strings[0].startswith(b"v=DMARC1"):
                dmarc_record = record.strings[0].decode('utf-8')
                results['DMARC Policy Exists'] = "PASS"
                results['DMARC Policy Not p=none'] = "PASS" if "p=none" not in dmarc_record else "FAIL: DMARC policy is p=none"
                results['DMARC Policy Percentage Default'] = "PASS" if "pct=100" in dmarc_record or "pct" not in dmarc_record else "FAIL: DMARC policy percentage is not default"
                return results
        results['DMARC Record Found'] = "FAIL: No DMARC record found"
    except Exception as e:
        results['DMARC Record Check Error'] = f"FAIL: {e}"
    return results

def check_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        if answers:
            return {"MX Records Check": "PASS"}
    except Exception as e:
        return {"MX Records Check": f"FAIL: {e}"}
    return {"MX Records Check": "FAIL: No MX records found"}

def perform_email_security_scan(domain):
    root_domain = extract_root_domain(domain)
    print(Fore.GREEN + f"Performing email security scan for: {root_domain}" + Style.RESET_ALL)

    results = {}
    results.update(check_spf_record(root_domain))
    results.update(check_dmarc_record(root_domain))
    results.update(check_mx_records(root_domain))

    filename = f"{root_domain}_email_scan.json"
    with open(filename, 'w') as file:
        json.dump(results, file, indent=4)

    for check, result in results.items():
        color = Fore.RED if "FAIL" in result else Fore.GREEN
        print(color + f"{check}: {result}" + Style.RESET_ALL)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Fore.RED + "Usage: python script.py <domain_name>" + Style.RESET_ALL)
        sys.exit(1)

    domain_name = sys.argv[1]
    perform_email_security_scan(domain_name)

