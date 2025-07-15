#!/usr/bin/env python3
"""
Security Vulnerability Scanner for Web Applications
Scans common security issues in HTML, CSS, and JavaScript files
"""

import os
import re
import json
from datetime import datetime
from typing import List, Dict, Any

class SecurityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.scan_results = {
            'timestamp': datetime.now().isoformat(),
            'total_files_scanned': 0,
            'vulnerabilities_found': 0,
            'severity_breakdown': {
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'details': []
        }
        
        # Common security patterns to check
        self.security_patterns = {
            'xss_potential': {
                'pattern': r'innerHTML\s*=\s*[^;]+(?:input|param|query|form)',
                'severity': 'high',
                'description': 'Potential XSS vulnerability through innerHTML manipulation'
            },
            'sql_injection': {
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*\+.*\+',
                'severity': 'high',
                'description': 'Potential SQL injection through string concatenation'
            },
            'insecure_eval': {
                'pattern': r'eval\s*\(',
                'severity': 'high',
                'description': 'Use of eval() function can lead to code injection'
            },
            'missing_csrf': {
                'pattern': r'<form[^>]*method\s*=\s*["\']post["\'][^>]*>(?!.*csrf)',
                'severity': 'medium',
                'description': 'Form missing CSRF protection'
            },
            'weak_password': {
                'pattern': r'password\s*=\s*["\'](?:password|123456|admin|root|user)["\']',
                'severity': 'high',
                'description': 'Hardcoded weak password detected'
            },
            'sensitive_data': {
                'pattern': r'(api_key|secret|password|token)\s*=\s*["\'][^"\']{5,}["\']',
                'severity': 'medium',
                'description': 'Potential sensitive data exposure'
            },
            'insecure_protocol': {
                'pattern': r'http://(?!localhost|127\.0\.0\.1)',
                'severity': 'low',
                'description': 'Insecure HTTP protocol usage'
            },
            'missing_input_validation': {
                'pattern': r'<input[^>]*(?!.*(?:required|pattern|min|max))[^>]*>',
                'severity': 'medium',
                'description': 'Input field without validation attributes'
            }
        }

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file for security vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                
            for vuln_type, config in self.security_patterns.items():
                matches = re.finditer(config['pattern'], content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vulnerability = {
                        'type': vuln_type,
                        'file': file_path,
                        'line': line_num,
                        'severity': config['severity'],
                        'description': config['description'],
                        'code_snippet': match.group(0)[:100] + '...' if len(match.group(0)) > 100 else match.group(0)
                    }
                    
                    vulnerabilities.append(vulnerability)
                    self.scan_results['severity_breakdown'][config['severity']] += 1
                    
        except Exception as e:
            print(f"Error scanning {file_path}: {str(e)}")
            
        return vulnerabilities

    def scan_directory(self, directory: str) -> Dict[str, Any]:
        """Scan all relevant files in a directory"""
        supported_extensions = {'.html', '.css', '.js', '.php', '.py', '.java', '.cpp', '.c'}
        
        for root, _, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in supported_extensions):
                    file_path = os.path.join(root, file)
                    file_vulnerabilities = self.scan_file(file_path)
                    
                    if file_vulnerabilities:
                        self.scan_results['details'].extend(file_vulnerabilities)
                        
                    self.scan_results['total_files_scanned'] += 1
        
        self.scan_results['vulnerabilities_found'] = len(self.scan_results['details'])
        return self.scan_results

    def generate_report(self, output_format: str = 'json') -> str:
        """Generate security report in specified format"""
        if output_format == 'json':
            return json.dumps(self.scan_results, indent=2)
        
        elif output_format == 'text':
            report = f"""
🔍 SECURITY SCAN REPORT
=======================
Scan Date: {self.scan_results['timestamp']}
Files Scanned: {self.scan_results['total_files_scanned']}
Vulnerabilities Found: {self.scan_results['vulnerabilities_found']}

SEVERITY BREAKDOWN:
🔴 High: {self.scan_results['severity_breakdown']['high']}
🟡 Medium: {self.scan_results['severity_breakdown']['medium']}
🟢 Low: {self.scan_results['severity_breakdown']['low']}

DETAILED FINDINGS:
==================
"""
            
            for vuln in self.scan_results['details']:
                severity_icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}
                report += f"""
{severity_icon[vuln['severity']]} {vuln['severity'].upper()} - {vuln['type']}
File: {vuln['file']}
Line: {vuln['line']}
Description: {vuln['description']}
Code: {vuln['code_snippet']}
{'='*50}
"""
            
            return report
        
        return "Unsupported format"

    def get_security_recommendations(self) -> List[str]:
        """Get security recommendations based on findings"""
        recommendations = []
        
        if self.scan_results['severity_breakdown']['high'] > 0:
            recommendations.append("🚨 CRITICAL: Address high-severity vulnerabilities immediately")
            recommendations.append("• Review all instances of eval(), innerHTML, and SQL queries")
            recommendations.append("• Implement proper input validation and sanitization")
            
        if self.scan_results['severity_breakdown']['medium'] > 0:
            recommendations.append("⚠️ WARNING: Medium-severity issues need attention")
            recommendations.append("• Add CSRF protection to all POST forms")
            recommendations.append("• Implement proper authentication and session management")
            
        if self.scan_results['severity_breakdown']['low'] > 0:
            recommendations.append("ℹ️ INFO: Low-severity issues for improvement")
            recommendations.append("• Use HTTPS instead of HTTP for all communications")
            recommendations.append("• Add security headers (CSP, HSTS, etc.)")
            
        if not any(self.scan_results['severity_breakdown'].values()):
            recommendations.append("✅ GOOD: No obvious security vulnerabilities detected")
            recommendations.append("• Continue following security best practices")
            recommendations.append("• Regular security audits are recommended")
            
        return recommendations

def main():
    """Main function to run security scan"""
    scanner = SecurityScanner()
    
    # Scan current directory
    current_dir = os.getcwd()
    print(f"🔍 Scanning directory: {current_dir}")
    print("=" * 50)
    
    # Perform scan
    results = scanner.scan_directory(current_dir)
    
    # Generate and display report
    print(scanner.generate_report('text'))
    
    # Show recommendations
    print("\n📋 SECURITY RECOMMENDATIONS:")
    print("=" * 30)
    for rec in scanner.get_security_recommendations():
        print(rec)
    
    # Save JSON report
    with open('security-report.json', 'w') as f:
        f.write(scanner.generate_report('json'))
    
    print(f"\n💾 Detailed report saved to: security-report.json")
    
    # Return exit code based on findings
    if results['severity_breakdown']['high'] > 0:
        print("\n❌ SCAN FAILED: Critical vulnerabilities found")
        return 1
    elif results['severity_breakdown']['medium'] > 0:
        print("\n⚠️ SCAN WARNING: Medium-severity issues found")
        return 2
    else:
        print("\n✅ SCAN PASSED: No critical issues found")
        return 0

if __name__ == "__main__":
    exit(main())
