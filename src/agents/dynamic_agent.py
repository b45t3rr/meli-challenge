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
from ..tools.database_tools import DatabaseUpdateTool, DatabaseCreateTool, DatabaseQueryTool
import logging

logger = logging.getLogger(__name__)

class DynamicAgent:
    """Agent responsible for dynamic vulnerability testing and exploitation"""
    
    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.network_tool = NetworkTool()
        self.db_update_tool = DatabaseUpdateTool()
        self.db_create_tool = DatabaseCreateTool()
        self.db_query_tool = DatabaseQueryTool()
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
            tools=[self.network_tool, self.db_update_tool, self.db_create_tool, self.db_query_tool],
            llm=self.llm,
            max_iter=15,
            memory=True
        )
    
    def test_vulnerabilities(self, target_url: str, vulnerabilities: List[Dict] = None, db_manager=None, document_id=None) -> Dict[str, Any]:
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
            # Update database with testing start status
            if db_manager and document_id:
                start_data = {
                    "status": "testing_started",
                    "target_url": target_url,
                    "vulnerabilities_to_test": len(vulnerabilities)
                }
                db_manager.update_assessment_stage(document_id, 'dynamic_analysis', start_data)
                logger.info(f"Database updated: Started testing {len(vulnerabilities)} vulnerabilities")
            
            # Test only the specific vulnerabilities from the report
            vulnerability_results = []
            for i, vuln in enumerate(vulnerabilities):
                result = self._test_specific_vulnerability(target_url, vuln)
                vulnerability_results.append(result)
                
                # Update database with each test result immediately
                if db_manager and document_id:
                    test_data = {
                        "status": "testing_in_progress",
                        "completed_tests": i + 1,
                        "total_tests": len(vulnerabilities),
                        "latest_test_result": result,
                        "exploitation_proofs": [r for r in vulnerability_results if r.get('dynamic_status') == 'Confirmed Vulnerable']
                    }
                    db_manager.update_assessment_stage(document_id, 'dynamic_analysis', test_data)
                    logger.info(f"Database updated: Completed test {i+1}/{len(vulnerabilities)} for {vuln.get('id', 'unknown')}")
            
            # Final update with all results
            if db_manager and document_id:
                final_data = {
                    "status": "testing_completed",
                    "vulnerability_tests": vulnerability_results,
                    "total_tested": len(vulnerability_results),
                    "confirmed_vulnerabilities": len([r for r in vulnerability_results if r.get('dynamic_status') == 'Confirmed Vulnerable']),
                    "target_url": target_url
                }
                db_manager.update_assessment_stage(document_id, 'dynamic_analysis', final_data)
                logger.info("Database updated: Dynamic testing completed with exploitation results")
            
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
            
            # If basic fields are missing, try to extract from proof_of_concept or affected_components
            if not endpoint or endpoint == '/':
                # Try to get from affected_components
                affected_components = vulnerability.get('affected_components', [])
                if affected_components:
                    endpoint = affected_components[0]
                
                # Try to extract from proof_of_concept
                poc = vulnerability.get('proof_of_concept', '')
                if poc and not endpoint:
                    # Extract endpoint from HTTP request in PoC
                    endpoint_match = re.search(r'(GET|POST|PUT|DELETE)\s+([^\s]+)', poc)
                    if endpoint_match:
                        method = endpoint_match.group(1)
                        endpoint = endpoint_match.group(2)
            
            # Extract method from proof_of_concept if not found
            if method == 'GET':
                poc = vulnerability.get('proof_of_concept', '')
                if 'POST' in poc:
                    method = 'POST'
                elif 'PUT' in poc:
                    method = 'PUT'
                elif 'DELETE' in poc:
                    method = 'DELETE'
            
            # Extract payload from proof_of_concept if not found
            if not payload:
                poc = vulnerability.get('proof_of_concept', '')
                if poc:
                    # For GET requests, extract from URL parameters
                    if method == 'GET' and '?' in poc:
                        query_part = poc.split('?', 1)[1].split(' ')[0]
                        payload = query_part
                    # For POST requests, extract payload from body
                    elif method == 'POST' and 'payload' in poc.lower():
                        payload_match = re.search(r"payload[\s=:]+['\"]([^'\"]+)['\"]|with payload[\s=:]+['\"]([^'\"]+)['\"]|username=([^&\s]+)|password=([^&\s]+)", poc, re.IGNORECASE)
                        if payload_match:
                            payload = next(group for group in payload_match.groups() if group)
                    # Extract common injection payloads
                    elif any(injection in poc.lower() for injection in ["' or", "<script", "../", "http://"]):
                        # Extract the actual malicious payload
                        payload_patterns = [
                             r"['\"]([^'\"]*(?:or|script|\.\.|\/)[^'\"]*)['\"]?",
                             r"=([^&\s]*(?:or|script|\.\.|\/)[^&\s]*)",
                             r"url=([^&\s]+)"
                         ]
                        for pattern in payload_patterns:
                            match = re.search(pattern, poc, re.IGNORECASE)
                            if match:
                                payload = match.group(1)
                                break
            
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
            
            # Use LLM to analyze response for any type of vulnerability
            success, evidence = self._analyze_vulnerability_response(response_text, payload, vulnerability)
            if success:
                attempt_result["success"] = True
                attempt_result["evidence"] = evidence
            
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
    
    def _analyze_vulnerability_response(self, response_text: str, payload: str, vulnerability: Dict) -> tuple[bool, str]:
        """Use LLM to analyze response for any type of vulnerability indicators"""
        try:
            vuln_type = vulnerability.get('type', 'Unknown')
            vuln_description = vulnerability.get('description', '')
            
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
            
            response = self.llm.invoke(analysis_prompt)
            
            # Handle empty or malformed responses
            if not response or not hasattr(response, 'content') or not response.content:
                logger.warning("LLM returned empty response, using fallback analysis")
                raise ValueError("Empty LLM response")
            
            response_content = response.content.strip()
            if not response_content:
                logger.warning("LLM returned empty content, using fallback analysis")
                raise ValueError("Empty LLM content")
            
            # Try to parse JSON response
            try:
                result = json.loads(response_content)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse LLM response as JSON: {response_content[:200]}...")
                # Try to extract JSON from response using regex
                import re
                json_match = re.search(r'\{.*\}', response_content, re.DOTALL)
                if json_match:
                    try:
                        result = json.loads(json_match.group())
                        logger.info("Successfully extracted JSON from LLM response")
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse extracted JSON from LLM response")
                        raise ValueError("Invalid JSON in LLM response")
                else:
                    logger.warning("No JSON found in LLM response")
                    raise ValueError("No JSON in LLM response")
            
            if result.get('vulnerable', False):
                return True, result.get('evidence', 'Vulnerability indicators detected')
            return False, result.get('evidence', 'No vulnerability indicators found')
            
        except Exception as e:
            logger.error(f"LLM analysis failed for vulnerability analysis: {e}")
            # Minimal fallback - just check for obvious error indicators
            response_lower = response_text.lower()
            error_indicators = ['error', 'exception', 'warning', 'failed', 'syntax', 'database', 'sql', 'uid=', 'root:', '/etc/', 'system32']
            for indicator in error_indicators:
                if indicator in response_lower:
                    return True, f"Potential vulnerability indicator detected: {indicator}"
            return False, 'No obvious vulnerability indicators found'