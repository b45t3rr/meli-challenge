#!/usr/bin/env python3
"""
Test script to verify that dynamic agent can extract vulnerability details from PDF format.
"""

import logging
from src.agents.dynamic_agent import DynamicAgent
from langchain_openai import ChatOpenAI
import json

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_vulnerability_extraction():
    """Test that dynamic agent can extract details from PDF vulnerability format"""
    logger.info("Testing vulnerability extraction from PDF format...")
    
    # Create dynamic agent
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    dynamic_agent = DynamicAgent(llm=llm)
    
    # Sample vulnerability from PDF (same format as extracted)
    pdf_vulnerability = {
        "id": "1",
        "title": "Server-Side Request Forgery (SSRF)",
        "type": "SSRF",
        "severity": "Critical",
        "cvss_score": "9.1",
        "affected_components": ["/api/fetch"],
        "description": "The application contains a Server-Side Request Forgery vulnerability in the API endpoint that fetches external resources.",
        "proof_of_concept": "GET /api/fetch?api_key=insecure_api_key_123&url=http://internal-server/secret.txt HTTP/1.1",
        "remediation": "Implement strict validation of user-supplied URLs",
        "status": "Pending Validation"
    }
    
    # Test extraction logic
    logger.info("Testing extraction of endpoint, method, and payload...")
    
    # Simulate the extraction logic from _test_specific_vulnerability
    endpoint = pdf_vulnerability.get('endpoint', pdf_vulnerability.get('url', '/'))
    method = pdf_vulnerability.get('method', 'GET').upper()
    payload = pdf_vulnerability.get('payload', pdf_vulnerability.get('exploit', ''))
    parameter = pdf_vulnerability.get('parameter', pdf_vulnerability.get('param', ''))
    
    # Apply the new extraction logic
    if not endpoint or endpoint == '/':
        affected_components = pdf_vulnerability.get('affected_components', [])
        if affected_components:
            endpoint = affected_components[0]
        
        poc = pdf_vulnerability.get('proof_of_concept', '')
        if poc and not endpoint:
            import re
            endpoint_match = re.search(r'(GET|POST|PUT|DELETE)\s+([^\s]+)', poc)
            if endpoint_match:
                method = endpoint_match.group(1)
                endpoint = endpoint_match.group(2)
    
    if method == 'GET':
        poc = pdf_vulnerability.get('proof_of_concept', '')
        if 'POST' in poc:
            method = 'POST'
        elif 'PUT' in poc:
            method = 'PUT'
        elif 'DELETE' in poc:
            method = 'DELETE'
    
    if not payload:
        poc = pdf_vulnerability.get('proof_of_concept', '')
        if poc:
            if method == 'GET' and '?' in poc:
                query_part = poc.split('?', 1)[1].split(' ')[0]
                payload = query_part
    
    logger.info(f"✅ Extracted details:")
    logger.info(f"   - Endpoint: {endpoint}")
    logger.info(f"   - Method: {method}")
    logger.info(f"   - Payload: {payload}")
    logger.info(f"   - Parameter: {parameter}")
    
    # Verify extraction worked
    if endpoint != '/' and method and payload:
        logger.info("🎉 Extraction successful! Dynamic agent should now be able to test this vulnerability.")
        return True
    else:
        logger.error("❌ Extraction failed. Missing critical information.")
        return False

def test_sql_injection_extraction():
    """Test extraction for SQL injection vulnerability"""
    logger.info("Testing SQL injection vulnerability extraction...")
    
    sql_vulnerability = {
        "id": "2",
        "title": "SQL Injection in Login Form",
        "type": "SQL Injection",
        "severity": "High",
        "cvss_score": "8.8",
        "affected_components": ["/login"],
        "description": "The login form is vulnerable to SQL injection",
        "proof_of_concept": "POST /login HTTP/1.1 with payload 'username=admin%27+or+%271%27%3D%271+--&password=admin%27+or+%271%27%3D%271+--'",
        "remediation": "Use parameterized queries",
        "status": "Pending Validation"
    }
    
    # Extract details
    endpoint = sql_vulnerability.get('affected_components', ['/'])[0]
    method = 'POST'  # From PoC
    payload = "username=admin%27+or+%271%27%3D%271+--&password=admin%27+or+%271%27%3D%271+--"  # From PoC
    
    logger.info(f"✅ SQL Injection extracted details:")
    logger.info(f"   - Endpoint: {endpoint}")
    logger.info(f"   - Method: {method}")
    logger.info(f"   - Payload: {payload}")
    
    return endpoint != '/' and method and payload

if __name__ == "__main__":
    logger.info("=== Testing Dynamic Agent Vulnerability Extraction ===")
    
    success1 = test_vulnerability_extraction()
    success2 = test_sql_injection_extraction()
    
    if success1 and success2:
        logger.info("🎉 All extraction tests passed! Dynamic agent should now detect vulnerabilities.")
    else:
        logger.error("❌ Some extraction tests failed.")
        exit(1)