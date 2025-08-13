#!/usr/bin/env python3

import os
import sys
import logging
from langchain_openai import ChatOpenAI
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_llm_prompt():
    """Test the improved LLM prompt for JSON response"""
    
    # Initialize LLM
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.1,
        api_key=os.getenv('OPENAI_API_KEY')
    )
    
    # Test prompt with SSRF scenario
    vuln_type = "SSRF"
    vuln_description = "Server-Side Request Forgery vulnerability"
    payload = "url=http://internal-server/secret.txt"
    response_text = "INTERNAL_SECRET_FLAG{ssrf_test_successful_internal_access}"
    
    analysis_prompt = f"""
    Analyze this HTTP response to determine if the reported vulnerability was successfully exploited.
    
    Vulnerability Details:
    - Type: {vuln_type}
    - Description: {vuln_description}
    - Payload used: {payload}
    
    HTTP Response (first 2000 chars): {response_text[:2000]}
    
    As a security expert, analyze the response for indicators that the vulnerability was successfully exploited.
    Consider:
    1. Error messages that reveal system information
    2. Unexpected content or data disclosure
    3. Reflected payloads or injected content
    4. System command outputs
    5. Database errors or information
    6. File system access indicators
    7. Any other signs specific to the vulnerability type
    
    IMPORTANT: Respond ONLY with valid JSON. Do NOT use markdown code blocks or any formatting. Return raw JSON only.
    
    Required JSON format:
    {{
        "vulnerable": true,
        "evidence": "specific evidence found or explanation why not vulnerable",
        "confidence": "high",
        "vulnerability_type_detected": "detected type if different from reported"
    }}
    """
    
    logger.info("Testing improved LLM prompt...")
    
    try:
        response = llm.invoke(analysis_prompt)
        response_content = response.content.strip()
        
        logger.info(f"LLM Response: {response_content}")
        
        # Try to parse as JSON directly
        try:
            result = json.loads(response_content)
            logger.info("✅ Successfully parsed JSON directly!")
            logger.info(f"Vulnerable: {result.get('vulnerable')}")
            logger.info(f"Evidence: {result.get('evidence')}")
            return True
        except json.JSONDecodeError as e:
            logger.warning(f"❌ Failed to parse JSON directly: {e}")
            logger.warning(f"Response starts with: {response_content[:100]}...")
            return False
            
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_llm_prompt()
    if success:
        print("🎉 LLM prompt test passed!")
    else:
        print("❌ LLM prompt test failed!")
        sys.exit(1)