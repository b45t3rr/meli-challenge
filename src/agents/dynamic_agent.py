from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json
import subprocess
import requests
import time
import re
from urllib.parse import urljoin, urlparse

from ..tools.network_tools import NetworkTool
import logging

logger = logging.getLogger(__name__)

class DynamicAgent:
    """Agent responsible for dynamic vulnerability testing and exploitation"""
    
    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.network_tool = NetworkTool()
        self.agent = self._create_agent()
        self.session = requests.Session()
        self.session.timeout = 30
    
    def _create_agent(self) -> Agent:
        """Create the dynamic analysis agent with ReAct methodology"""
        return Agent(
            role="Dynamic Security Testing Expert",
            goal="Perform live exploitation testing to validate vulnerabilities against running applications",
            backstory="""
            You are an expert vulnerability validation specialist focused on testing specific 
            vulnerabilities exactly as reported. You do NOT perform reconnaissance or general 
            security testing - you only validate reported vulnerabilities using the exact 
            mechanisms, payloads, and parameters specified in the vulnerability reports.
            
            Your focused process:
            1. Extract exact vulnerability details from reports (endpoint, method, payload, parameter)
            2. Execute the precise test using the reported mechanism
            3. Analyze response for vulnerability indicators specific to the reported type
            4. Determine if the vulnerability can be reproduced as reported
            
            You excel at:
            - Reproducing exact vulnerability conditions
            - Using reported payloads and parameters precisely
            - Analyzing responses for specific vulnerability indicators
            - Validating vulnerability existence without additional testing
            
            You test only what is reported, nothing more, nothing less.
            """,
            verbose=True,
            allow_delegation=False,
            tools=[self.network_tool],
            llm=self.llm,
            max_iter=15,
            memory=True
        )
    
    def test_vulnerabilities(self, target_url: str, vulnerabilities: List[Dict] = None) -> Dict[str, Any]:
        """Test specific vulnerabilities from the report using exact mechanisms and payloads"""
        logger.info(f"Starting targeted vulnerability testing on: {target_url}")
        
        if not vulnerabilities:
            logger.warning("No vulnerabilities provided for testing")
            return {
                "target_url": target_url,
                "vulnerability_tests": [],
                "message": "No vulnerabilities to test"
            }
        
        try:
            # Test only the specific vulnerabilities from the report
            vulnerability_results = []
            for vuln in vulnerabilities:
                result = self._test_specific_vulnerability(target_url, vuln)
                vulnerability_results.append(result)
            
            return {
                "target_url": target_url,
                "vulnerability_tests": vulnerability_results,
                "total_tested": len(vulnerability_results)
            }
            
        except Exception as e:
            logger.error(f"Vulnerability testing failed: {e}")
            raise
    
    # Reconnaissance methods removed - agent now focuses only on testing specific vulnerabilities
    
    def _test_specific_vulnerability(self, target_url: str, vulnerability: Dict) -> Dict[str, Any]:
        """Test a specific vulnerability using exact details from the report"""
        vuln_id = vulnerability.get('id', 'unknown')
        vuln_type = vulnerability.get('type', '').lower()
        
        logger.info(f"Testing reported vulnerability: {vuln_id} ({vuln_type})")
        
        test_result = {
            "vulnerability_id": vuln_id,
            "type": vuln_type,
            "dynamic_status": "Not Vulnerable",
            "test_attempts": [],
            "evidence": [],
            "confidence": "Low",
            "report_details": vulnerability
        }
        
        try:
            # Extract specific details from the vulnerability report
            endpoint = vulnerability.get('endpoint', vulnerability.get('url', '/'))
            method = vulnerability.get('method', 'GET').upper()
            payload = vulnerability.get('payload', vulnerability.get('exploit', ''))
            parameter = vulnerability.get('parameter', vulnerability.get('param', ''))
            
            # Create test attempt based on report details
            test_attempt = {
                "name": f"Test {vuln_id} as reported",
                "method": method,
                "endpoint": endpoint,
                "payload": payload,
                "parameter": parameter,
                "description": vulnerability.get('description', '')
            }
            
            # Execute the exact test from the report
            attempt_result = self._execute_reported_test(target_url, test_attempt, vulnerability)
            test_result["test_attempts"].append(attempt_result)
            
            # Evaluate results
            if attempt_result.get('success', False):
                test_result["dynamic_status"] = "Confirmed Vulnerable"
                test_result["evidence"].append(attempt_result.get('evidence', ''))
                test_result["confidence"] = "High"
            elif attempt_result.get('possible', False):
                test_result["dynamic_status"] = "Possibly Vulnerable"
                test_result["confidence"] = "Medium"
            else:
                test_result["dynamic_status"] = "Not Reproducible"
                test_result["confidence"] = "Low"
            
        except Exception as e:
            logger.error(f"Error testing vulnerability {vuln_id}: {e}")
            test_result["error"] = str(e)
        
        return test_result
    
    # LLM testing plan methods removed - agent now uses direct vulnerability report details
    
    def _execute_reported_test(self, target_url: str, test_attempt: Dict, vulnerability: Dict) -> Dict[str, Any]:
        """Execute a test based on exact vulnerability report details"""
        
        attempt_result = {
            "test_name": test_attempt.get('name', 'Unknown'),
            "success": False,
            "possible": False,
            "response_code": None,
            "response_time": None,
            "evidence": "",
            "error": None,
            "request_details": test_attempt
        }
        
        try:
            # Prepare request based on report details
            method = test_attempt.get('method', 'GET').upper()
            endpoint = test_attempt.get('endpoint', '/')
            payload = test_attempt.get('payload', '')
            parameter = test_attempt.get('parameter', '')
            
            # Construct the target URL
            test_url = urljoin(target_url, endpoint)
            
            headers = {'User-Agent': 'VulnerabilityValidator/1.0'}
            data = {}
            
            # Apply payload based on method and parameter
            start_time = time.time()
            
            if method == 'GET':
                if parameter and payload:
                    test_url += f"?{parameter}={payload}" if '?' not in test_url else f"&{parameter}={payload}"
                elif payload:
                    test_url += f"?{payload}" if '?' not in test_url else f"&{payload}"
                response = self.session.get(test_url, headers=headers)
            
            elif method == 'POST':
                if parameter and payload:
                    data[parameter] = payload
                elif payload:
                    # Try to parse payload as form data or use as raw data
                    if '=' in payload:
                        for pair in payload.split('&'):
                            if '=' in pair:
                                key, value = pair.split('=', 1)
                                data[key] = value
                    else:
                        data['data'] = payload
                response = self.session.post(test_url, headers=headers, data=data)
            
            else:
                # For other methods (PUT, DELETE, etc.)
                if parameter and payload:
                    data[parameter] = payload
                response = self.session.request(method, test_url, headers=headers, data=data)
            
            response_time = time.time() - start_time
            
            # Update result with response details
            attempt_result.update({
                "response_code": response.status_code,
                "response_time": response_time,
                "response_headers": dict(response.headers),
                "response_size": len(response.content),
                "test_url": test_url
            })
            
            # Analyze response for vulnerability indicators
            response_text = response.text
            response_lower = response_text.lower()
            
            # Check for specific indicators based on vulnerability type
            vuln_type = vulnerability.get('type', '').lower()
            
            if 'xss' in vuln_type or 'cross-site scripting' in vuln_type:
                if payload in response_text:
                    attempt_result["success"] = True
                    attempt_result["evidence"] = f"XSS payload '{payload}' reflected in response"
            
            elif 'sql' in vuln_type or 'injection' in vuln_type:
                sql_errors = ['sql syntax', 'mysql', 'oracle', 'postgresql', 'sqlite', 'syntax error', 'database error']
                for error in sql_errors:
                    if error in response_lower:
                        attempt_result["success"] = True
                        attempt_result["evidence"] = f"SQL error detected: {error}"
                        break
            
            elif 'command' in vuln_type or 'rce' in vuln_type:
                command_indicators = ['uid=', 'gid=', 'root:', 'administrator', 'system32', '/bin/', '/usr/']
                for indicator in command_indicators:
                    if indicator in response_lower:
                        attempt_result["success"] = True
                        attempt_result["evidence"] = f"Command execution indicator: {indicator}"
                        break
            
            elif 'directory' in vuln_type or 'path traversal' in vuln_type:
                path_indicators = ['root:', '[drivers]', 'localhost', '/etc/passwd', 'windows\\system32']
                for indicator in path_indicators:
                    if indicator in response_lower:
                        attempt_result["success"] = True
                        attempt_result["evidence"] = f"Path traversal indicator: {indicator}"
                        break
            
            # Generic checks if no specific type matched
            if not attempt_result["success"]:
                # Check for error responses that might indicate vulnerability
                if response.status_code >= 500:
                    attempt_result["possible"] = True
                    attempt_result["evidence"] = f"Server error response: {response.status_code}"
                
                elif response_time > 5.0:
                    attempt_result["possible"] = True
                    attempt_result["evidence"] = f"Unusual response time: {response_time:.2f}s (possible time-based attack)"
                
                elif any(error in response_lower for error in ['error', 'exception', 'warning', 'failed']):
                    attempt_result["possible"] = True
                    attempt_result["evidence"] = "Error messages detected in response"
            
        except Exception as e:
            attempt_result["error"] = str(e)
            logger.error(f"Test execution failed: {e}")
        
        return attempt_result
    
    # Old test execution methods removed - replaced with _execute_reported_test
    
    # General testing methods removed - agent now focuses only on specific vulnerabilities from reports
    
    # All auxiliary methods removed - agent now focuses only on testing specific reported vulnerabilities