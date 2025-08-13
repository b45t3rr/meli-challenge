from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json
from datetime import datetime

from ..tools.database_tools import DatabaseUpdateTool, DatabaseCreateTool, DatabaseQueryTool
import logging

logger = logging.getLogger(__name__)

class TriageAgent:
    """Agent responsible for triaging and consolidating vulnerability assessments"""
    
    def __init__(self, llm: ChatOpenAI, language: str = "en"):
        self.llm = llm
        self.language = language
        self.db_update_tool = DatabaseUpdateTool()
        self.db_create_tool = DatabaseCreateTool()
        self.db_query_tool = DatabaseQueryTool()
        self.agent = self._create_agent()
    
    def _create_agent(self) -> Agent:
        """Create the triage agent with ReAct methodology"""
        return Agent(
            role="Vulnerability Triage Specialist",
            goal="Consolidate and triage vulnerability assessments from multiple analysis sources to provide final vulnerability status",
            backstory="""
            You are a senior cybersecurity analyst specialized in vulnerability triage and risk assessment. 
            You follow the ReAct methodology (Reasoning and Action) to systematically analyze and 
            consolidate findings from multiple security assessment sources.
            
            Your process:
            1. REASON: Analyze findings from PDF analysis, static analysis, and dynamic testing
            2. ACT: Correlate evidence across different analysis methods
            3. REASON: Evaluate the strength and reliability of each evidence source
            4. ACT: Assign final vulnerability status based on comprehensive evidence
            5. REASON: Prioritize vulnerabilities based on exploitability and impact
            
            Your decision criteria:
            - If dynamic testing confirms exploitation: Status = Vulnerable
            - If static analysis finds exploitable code + dynamic shows indicators: Status = Vulnerable
            - If only static analysis finds issues without dynamic confirmation: Status = Possible
            - If no evidence found in any analysis: Status = Not Vulnerable
            
            You excel at:
            - Evidence correlation and analysis
            - Risk-based vulnerability prioritization
            - False positive identification and filtering
            - Comprehensive vulnerability reporting
            - Security recommendation formulation
            """,
            verbose=True,
            allow_delegation=False,
            tools=[self.db_update_tool, self.db_create_tool, self.db_query_tool],
            llm=self.llm,
            max_iter=5,
            memory=True
        )
    
    def triage_vulnerabilities(self, 
                             pdf_analysis: Dict = None, 
                             static_analysis: Dict = None, 
                             dynamic_analysis: Dict = None,
                             db_manager=None,
                             document_id=None) -> Dict[str, Any]:
        """Perform comprehensive triage of all vulnerability findings"""
        logger.info("Starting vulnerability triage process")
        
        try:
            # Extract vulnerabilities from each source
            pdf_vulns = self._extract_pdf_vulnerabilities(pdf_analysis)
            static_results = self._extract_static_results(static_analysis)
            dynamic_results = self._extract_dynamic_results(dynamic_analysis)
            
            # Perform triage analysis using LLM
            triage_result = self._perform_triage_analysis(pdf_vulns, static_results, dynamic_results)
            
            # Generate final report
            final_report = self._generate_final_report(triage_result, pdf_analysis, static_analysis, dynamic_analysis)
            
            return final_report
            
        except Exception as e:
            logger.error(f"Triage process failed: {e}")
            raise
    
    def _extract_pdf_vulnerabilities(self, pdf_analysis) -> List[Dict]:
        """Extract vulnerability information from PDF analysis"""
        if not pdf_analysis:
            return []
        
        # Handle both dict and string inputs
        if isinstance(pdf_analysis, dict):
            # Already a dictionary, extract vulnerabilities directly
            vulnerabilities = pdf_analysis.get('vulnerabilities', [])
            logger.info(f"Extracted {len(vulnerabilities)} vulnerabilities from PDF analysis")
            return vulnerabilities
        elif isinstance(pdf_analysis, str):
            try:
                pdf_analysis = json.loads(pdf_analysis)
                vulnerabilities = pdf_analysis.get('vulnerabilities', [])
                logger.info(f"Parsed and extracted {len(vulnerabilities)} vulnerabilities from PDF analysis string")
                return vulnerabilities
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse PDF analysis as JSON: {pdf_analysis[:200]}...")
                # Try to extract JSON from string using regex
                import re
                json_match = re.search(r'\{.*\}', pdf_analysis, re.DOTALL)
                if json_match:
                    try:
                        pdf_analysis = json.loads(json_match.group())
                        vulnerabilities = pdf_analysis.get('vulnerabilities', [])
                        logger.info(f"Successfully extracted {len(vulnerabilities)} vulnerabilities from JSON in string")
                        return vulnerabilities
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse extracted JSON from PDF analysis")
                        return []
                else:
                    logger.warning("No JSON found in PDF analysis string")
                    return []
        else:
            logger.warning(f"Unexpected PDF analysis type: {type(pdf_analysis)}")
            return []
    
    def _extract_static_results(self, static_analysis) -> Dict[str, Any]:
        """Extract results from static analysis"""
        if not static_analysis:
            return {"vulnerability_assessments": [], "additional_findings": []}
        
        # Handle both dict and string inputs
        if isinstance(static_analysis, dict):
            # Already a dictionary, extract data directly
            vuln_analysis = static_analysis.get('vulnerability_analysis', {})
            assessments = vuln_analysis.get('vulnerability_assessments', [])
            additional = vuln_analysis.get('additional_findings', [])
            logger.info(f"Extracted {len(assessments)} vulnerability assessments from static analysis")
        elif isinstance(static_analysis, str):
            try:
                static_analysis = json.loads(static_analysis)
                vuln_analysis = static_analysis.get('vulnerability_analysis', {})
                assessments = vuln_analysis.get('vulnerability_assessments', [])
                additional = vuln_analysis.get('additional_findings', [])
                logger.info(f"Parsed and extracted {len(assessments)} vulnerability assessments from static analysis string")
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse static analysis as JSON: {static_analysis[:200]}...")
                # Try to extract JSON from string using regex
                import re
                json_match = re.search(r'\{.*\}', static_analysis, re.DOTALL)
                if json_match:
                    try:
                        static_analysis = json.loads(json_match.group())
                        vuln_analysis = static_analysis.get('vulnerability_analysis', {})
                        assessments = vuln_analysis.get('vulnerability_assessments', [])
                        additional = vuln_analysis.get('additional_findings', [])
                        logger.info(f"Successfully extracted {len(assessments)} vulnerability assessments from JSON in string")
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse extracted JSON from static analysis")
                        return {"vulnerability_assessments": [], "additional_findings": []}
                else:
                    logger.warning("No JSON found in static analysis string")
                    return {"vulnerability_assessments": [], "additional_findings": []}
        else:
            logger.warning(f"Unexpected static analysis type: {type(static_analysis)}")
            return {"vulnerability_assessments": [], "additional_findings": []}
        return {
            "vulnerability_assessments": assessments,
            "additional_findings": additional,
            "semgrep_results": static_analysis.get('semgrep_results', {})
        }
    
    def _extract_dynamic_results(self, dynamic_analysis) -> Dict[str, Any]:
        """Extract results from dynamic analysis"""
        if not dynamic_analysis:
            return {"vulnerability_tests": [], "general_tests": {}}
        
        # Handle both dict and string inputs
        if isinstance(dynamic_analysis, str):
            try:
                dynamic_analysis = json.loads(dynamic_analysis)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse dynamic analysis as JSON: {dynamic_analysis[:200]}...")
                # Try to extract JSON from string using regex
                import re
                json_match = re.search(r'\{.*\}', dynamic_analysis, re.DOTALL)
                if json_match:
                    try:
                        dynamic_analysis = json.loads(json_match.group())
                        logger.info("Successfully extracted JSON from dynamic analysis string")
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse extracted JSON from dynamic analysis")
                        return {"vulnerability_tests": [], "general_tests": {}}
                else:
                    logger.warning("No JSON found in dynamic analysis string")
                    return {"vulnerability_tests": [], "general_tests": {}}
        
        vuln_tests = dynamic_analysis.get('vulnerability_tests', [])
        general_tests = dynamic_analysis.get('general_tests', {})
        
        logger.info(f"Extracted {len(vuln_tests)} vulnerability tests from dynamic analysis")
        return {
            "vulnerability_tests": vuln_tests,
            "general_tests": general_tests,
            "reconnaissance": dynamic_analysis.get('reconnaissance', {})
        }
    
    def _perform_triage_analysis(self, pdf_vulns: List[Dict], static_results: Dict, dynamic_results: Dict) -> Dict[str, Any]:
        """Perform comprehensive triage analysis using LLM with ReAct methodology"""
        
        # Prepare context for LLM
        pdf_context = json.dumps(pdf_vulns[:10], indent=2)  # Limit to first 10 for token management
        static_context = json.dumps(static_results, indent=2)
        dynamic_context = json.dumps(dynamic_results, indent=2)
        
        # Language mapping for instructions
        language_instructions = {
            "en": "Provide your analysis and final report in English.",
            "es": "Proporciona tu análisis y reporte final en español.",
            "fr": "Fournissez votre analyse et rapport final en français.",
            "de": "Stellen Sie Ihre Analyse und den Abschlussbericht auf Deutsch zur Verfügung.",
            "it": "Fornisci la tua analisi e il rapporto finale in italiano.",
            "pt": "Forneça sua análise e relatório final em português."
        }
        
        language_instruction = language_instructions.get(self.language, language_instructions["en"])
        
        prompt = f"""
        As a vulnerability triage specialist following ReAct methodology, analyze these findings:
        
        REASONING: I need to correlate findings from PDF analysis, static code analysis, and dynamic testing to determine final vulnerability status.
        
        PDF ANALYSIS FINDINGS:
        {pdf_context}
        
        STATIC ANALYSIS RESULTS:
        {static_context}
        
        DYNAMIC TESTING RESULTS:
        {dynamic_context}

        IMPORTANT: I MUST ONLY WORK WITH THE VULNERABILITIES REPORTED IN THE PDF ANALYSIS FINDINGS. ANY OTHERS FINIDINGS MUST BE DISCARDED.
        
        ACTION: For each vulnerability, I will:
        1. Correlate findings across all three analysis methods
        2. Evaluate the strength of evidence from each source
        3. Apply decision criteria to determine final status
        4. Prioritize based on exploitability and impact
        5. Recategorize the severity based on the real impact on the system
        6. Extract detailed technical evidence including:
           - Exact vulnerable code snippets from static analysis
           - File locations and line numbers where vulnerabilities exist
           - HTTP requests and responses from dynamic testing
           - Specific exploitation payloads used
           - Step-by-step proof of concept for exploitation
        
        REASONING: My decision criteria are:
        - VULNERABLE: Dynamic testing confirms exploitation OR there is static evidence
        - POSSIBLE: Only static analysis finds issues without dynamic confirmation
        - NOT VULNERABLE: No credible evidence found in any analysis
        
        TECHNICAL EVIDENCE EXTRACTION GUIDELINES:
        - From STATIC ANALYSIS: Extract exact code snippets, file paths, line numbers from semgrep_results
        - From DYNAMIC TESTING: Extract HTTP requests, responses, payloads from vulnerability_tests
        - Provide concrete examples, not generic descriptions
        - Include actual exploitation steps when available
        - Reference specific tools output (Semgrep findings, HTTP responses, etc.)
        
        IMPORTANT: {language_instruction}
        
        Provide comprehensive triage analysis in this JSON format:
        {{
            "triage_summary": {{
                "total_vulnerabilities_analyzed": "number",
                "confirmed_vulnerable": "number",
                "possible_vulnerable": "number",
                "not_vulnerable": "number",
                "high_priority_count": "number"
            }},
            "vulnerability_triage": [
                {{
                    "vulnerability_id": "string",
                    "title": "string",
                    "type": "string",
                    "original_severity": "string",
                    "final_status": "Vulnerable|Not Vulnerable",
                    "confidence_level": "High|Medium|Low",
                    "priority": "Critical|High|Medium|Low",
                    "evidence_summary": {{
                        "pdf_evidence": "string",
                        "static_evidence": "string",
                        "dynamic_evidence": "string"
                    }},
                    "technical_evidence": {{
                        "vulnerable_code_snippet": "string - exact code that contains the vulnerability",
                        "file_location": "string - file path and line numbers",
                        "http_request_example": "string - example HTTP request that exploits the vulnerability",
                        "http_response_example": "string - example HTTP response showing the vulnerability",
                        "exploitation_payload": "string - specific payload used to exploit",
                        "proof_of_concept": "string - step by step exploitation process"
                    }},
                    "correlation_analysis": "string",
                    "exploitability_assessment": "string",
                    "risk_rating": "string",
                    "remediation_priority": "string",
                    "false_positive_likelihood": "string"
                }}
            ],
            "additional_security_issues": [
                {{
                    "type": "string",
                    "description": "string",
                    "severity": "string",
                    "source": "static|dynamic",
                    "recommendation": "string"
                }}
            ],
            "methodology_effectiveness": {{
                "pdf_analysis_quality": "string",
                "static_analysis_coverage": "string",
                "dynamic_testing_depth": "string",
                "overall_assessment_confidence": "string"
            }},
            "recommendations": [
                "string"
            ]
        }}
        """
        
        try:
            response = self.llm.invoke(prompt)
            
            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                try:
                    triage_data = json.loads(json_match.group())
                    
                    # Enhance technical evidence with actual data from agents
                    if 'vulnerability_triage' in triage_data:
                        for vuln_triage in triage_data['vulnerability_triage']:
                            vuln_id = vuln_triage.get('vulnerability_id')
                            if vuln_id:
                                # Extract and update technical evidence
                                enhanced_evidence = self._extract_technical_evidence(vuln_id, static_results, dynamic_results)
                                vuln_triage['technical_evidence'] = enhanced_evidence
                    
                    logger.info("Successfully parsed triage analysis")
                    return triage_data
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse triage JSON: {e}")
                    return self._create_fallback_triage(pdf_vulns, static_results, dynamic_results)
            else:
                logger.warning("No JSON found in triage response")
                return self._create_fallback_triage(pdf_vulns, static_results, dynamic_results)
                
        except Exception as e:
            logger.error(f"Triage analysis failed: {e}")
            return self._create_fallback_triage(pdf_vulns, static_results, dynamic_results)
    
    def _create_fallback_triage(self, pdf_vulns: List[Dict], static_results: Dict, dynamic_results: Dict) -> Dict[str, Any]:
        """Create fallback triage when LLM analysis fails"""
        logger.info("Creating fallback triage analysis")
        
        # Simple rule-based triage
        vulnerability_triage = []
        
        for vuln in pdf_vulns:
            vuln_id = vuln.get('id', 'unknown')
            
            # Check dynamic results
            dynamic_status = "Not Vulnerable"
            dynamic_evidence = "No dynamic testing performed"
            
            for dyn_test in dynamic_results.get('vulnerability_tests', []):
                if dyn_test.get('vulnerability_id') == vuln_id:
                    dynamic_status = dyn_test.get('dynamic_status', 'Not Vulnerable')
                    dynamic_evidence = f"Dynamic testing: {dynamic_status}"
                    break
            
            # Check static results
            static_status = "Not Vulnerable"
            static_evidence = "No static analysis performed"
            
            for static_assess in static_results.get('vulnerability_assessments', []):
                if static_assess.get('vulnerability_id') == vuln_id:
                    static_status = static_assess.get('static_status', 'Not Vulnerable')
                    static_evidence = f"Static analysis: {static_status}"
                    break
            
            # Determine final status
            if dynamic_status == "Vulnerable" or static_status == "Vulnerable":
                final_status = "Vulnerable"
                confidence = "High" if dynamic_status == "Vulnerable" else "Medium"
            else:
                final_status = "Not Vulnerable"
                confidence = "Low"
            
            vulnerability_triage.append({
                "vulnerability_id": vuln_id,
                "title": vuln.get('title', 'Unknown'),
                "type": vuln.get('type', 'Unknown'),
                "original_severity": vuln.get('severity', 'Unknown'),
                "final_status": final_status,
                "confidence_level": confidence,
                "priority": self._calculate_priority(vuln.get('severity', 'Medium'), final_status),
                "evidence_summary": {
                    "pdf_evidence": f"Reported in PDF: {vuln.get('title', 'Unknown')}",
                    "static_evidence": static_evidence,
                    "dynamic_evidence": dynamic_evidence
                },
                "technical_evidence": self._extract_technical_evidence(vuln_id, static_results, dynamic_results),
                "correlation_analysis": "Automated correlation (fallback mode)",
                "exploitability_assessment": "Limited assessment available",
                "risk_rating": "Medium",
                "remediation_priority": "Medium",
                "false_positive_likelihood": "Unknown"
            })
        
        # Count statuses
        vulnerable_count = sum(1 for v in vulnerability_triage if v['final_status'] == 'Vulnerable')
        not_vulnerable_count = len(vulnerability_triage) - vulnerable_count
        
        return {
            "triage_summary": {
                "total_vulnerabilities_analyzed": len(vulnerability_triage),
                "confirmed_vulnerable": vulnerable_count,
                "possible_vulnerable": 0,
                "not_vulnerable": not_vulnerable_count,
                "high_priority_count": sum(1 for v in vulnerability_triage if v['priority'] in ['Critical', 'High'])
            },
            "vulnerability_triage": vulnerability_triage,
            "additional_security_issues": [],
            "methodology_effectiveness": {
                "pdf_analysis_quality": "Limited",
                "static_analysis_coverage": "Basic",
                "dynamic_testing_depth": "Basic",
                "overall_assessment_confidence": "Low"
            },
            "recommendations": self._get_fallback_recommendations(),
            "fallback_mode": True
        }
    
    def _extract_technical_evidence(self, vuln_id: str, static_analysis: Dict, dynamic_analysis: Dict) -> Dict[str, str]:
        """Extract technical evidence and proof of concept from static and dynamic analysis"""
        technical_evidence = {
            "vulnerable_code_snippet": "No code evidence found",
            "file_location": "No location identified",
            "http_request_example": "No HTTP request captured",
            "http_response_example": "No HTTP response captured",
            "exploitation_payload": "No payload identified",
            "proof_of_concept": "No proof of concept available"
        }
        
        # Extract from static analysis
        if static_analysis and 'vulnerability_analysis' in static_analysis:
            vuln_assessments = static_analysis['vulnerability_analysis'].get('vulnerability_assessments', [])
            for assessment in vuln_assessments:
                if assessment.get('vulnerability_id') == vuln_id:
                    # Extract code evidence from static analysis
                    if assessment.get('code_locations'):
                        technical_evidence['file_location'] = '; '.join(assessment['code_locations'])
                    
                    # Extract Semgrep findings as code snippets
                    if assessment.get('semgrep_matches'):
                        technical_evidence['vulnerable_code_snippet'] = '; '.join(assessment['semgrep_matches'])
                    
                    # Create static analysis proof of concept
                    if assessment.get('evidence'):
                        technical_evidence['proof_of_concept'] = f"Static Analysis PoC: {assessment['evidence']}"
                    break
        
        # Extract from dynamic analysis
        if dynamic_analysis and 'vulnerability_tests' in dynamic_analysis:
            vuln_tests = dynamic_analysis['vulnerability_tests']
            for test in vuln_tests:
                if test.get('vulnerability_id') == vuln_id:
                    # Extract HTTP request/response from test attempts
                    test_attempts = test.get('test_attempts', [])
                    for attempt in test_attempts:
                        if attempt.get('request_details'):
                            req_details = attempt['request_details']
                            method = req_details.get('method', 'GET')
                            endpoint = req_details.get('endpoint', '/')
                            payload = req_details.get('payload', '')
                            parameter = req_details.get('parameter', '')
                            
                            # Build HTTP request example
                            if method and endpoint:
                                if method == 'GET' and payload:
                                    param_str = f"?{parameter}={payload}" if parameter else f"?{payload}"
                                    technical_evidence['http_request_example'] = f"{method} {endpoint}{param_str} HTTP/1.1"
                                elif method == 'POST' and payload:
                                    technical_evidence['http_request_example'] = f"{method} {endpoint} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{parameter}={payload}" if parameter else f"{method} {endpoint} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{payload}"
                            
                            # Extract payload
                            if payload:
                                technical_evidence['exploitation_payload'] = payload
                        
                        # Extract HTTP response
                        if attempt.get('response_code'):
                            response_code = attempt['response_code']
                            response_size = attempt.get('response_size', 'unknown')
                            technical_evidence['http_response_example'] = f"HTTP/1.1 {response_code}\nContent-Length: {response_size}"
                        
                        # Create dynamic analysis proof of concept
                        if attempt.get('evidence'):
                            if technical_evidence['proof_of_concept'] == "No proof of concept available":
                                technical_evidence['proof_of_concept'] = f"Dynamic Analysis PoC: {attempt['evidence']}"
                            else:
                                technical_evidence['proof_of_concept'] += f"; Dynamic Analysis PoC: {attempt['evidence']}"
                    break
        
        return technical_evidence
    
    def _get_fallback_recommendations(self) -> List[str]:
        """Generate fallback recommendations in the specified language"""
        recommendations = {
            "en": [
                "Manual review recommended due to automated triage limitations",
                "Consider additional testing for high-severity vulnerabilities"
            ],
            "es": [
                "Se recomienda revisión manual debido a limitaciones del triaje automatizado",
                "Considerar pruebas adicionales para vulnerabilidades de alta severidad"
            ]
        }
        
        return recommendations.get(self.language, recommendations["en"])
    
    def _calculate_priority(self, original_severity: str, final_status: str) -> str:
        """Calculate priority based on severity and status"""
        if final_status != "Vulnerable":
            return "Low"
        
        severity_map = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }
        
        return severity_map.get(original_severity, "Medium")
    
    def _generate_final_report(self, triage_result: Dict, pdf_analysis: Dict, static_analysis: Dict, dynamic_analysis: Dict) -> Dict[str, Any]:
        """Generate the final comprehensive report"""
        logger.info("Generating final vulnerability assessment report")
        
        final_report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "analysis_type": "Comprehensive Vulnerability Validation",
                "methodology": "ReAct-based Multi-Agent Analysis",
                "tools_used": ["PDF Analysis", "Semgrep Static Analysis", "Dynamic Testing"]
            },
            "executive_summary": self._generate_executive_summary(triage_result),
            "vulnerability_summary": triage_result.get('triage_summary', {}),
            "vulnerabilities": triage_result.get('vulnerability_triage', []),
            "additional_findings": triage_result.get('additional_security_issues', []),
            "methodology_assessment": triage_result.get('methodology_effectiveness', {}),
            "recommendations": triage_result.get('recommendations', []),
            "detailed_analysis": {
                "pdf_analysis": pdf_analysis,
                "static_analysis": static_analysis,
                "dynamic_analysis": dynamic_analysis
            },
            "risk_matrix": self._generate_risk_matrix(triage_result.get('vulnerability_triage', [])),
            "next_steps": self._generate_next_steps(triage_result)
        }
        
        return final_report
    
    def _generate_executive_summary(self, triage_result: Dict) -> str:
        """Generate executive summary in the specified language"""
        summary = triage_result.get('triage_summary', {})
        total = summary.get('total_vulnerabilities_analyzed', 0)
        vulnerable = summary.get('confirmed_vulnerable', 0)
        not_vulnerable = summary.get('not_vulnerable', 0)
        high_priority = summary.get('high_priority_count', 0)
        
        # Language-specific templates
        templates = {
            "en": f"""
        Comprehensive vulnerability validation analysis completed using multi-agent ReAct methodology.
        
        Analysis Results:
        - Total vulnerabilities analyzed: {total}
        - Confirmed vulnerable: {vulnerable}
        - Not vulnerable: {not_vulnerable}
        - High priority issues: {high_priority}
        
        The analysis combined PDF report interpretation, static code analysis using Semgrep, 
        and dynamic exploitation testing to provide comprehensive vulnerability validation.
        
        {f'Critical attention required for {vulnerable} confirmed vulnerabilities.' if vulnerable > 0 else 'No confirmed vulnerabilities found in the current analysis.'}
        """,
            "es": f"""
        Análisis integral de validación de vulnerabilidades completado utilizando metodología ReAct multi-agente.
        
        Resultados del Análisis:
        - Total de vulnerabilidades analizadas: {total}
        - Confirmadas como vulnerables: {vulnerable}
        - No vulnerables: {not_vulnerable}
        - Problemas de alta prioridad: {high_priority}
        
        El análisis combinó interpretación de reportes PDF, análisis estático de código usando Semgrep, 
        y pruebas dinámicas de explotación para proporcionar validación integral de vulnerabilidades.
        
        {f'Se requiere atención crítica para {vulnerable} vulnerabilidades confirmadas.' if vulnerable > 0 else 'No se encontraron vulnerabilidades confirmadas en el análisis actual.'}
        """
        }
        
        return templates.get(self.language, templates["en"])
    
    def _generate_risk_matrix(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Generate risk matrix for vulnerabilities"""
        risk_matrix = {
            "Critical": {"Vulnerable": 0, "Not Vulnerable": 0},
            "High": {"Vulnerable": 0, "Not Vulnerable": 0},
            "Medium": {"Vulnerable": 0, "Not Vulnerable": 0},
            "Low": {"Vulnerable": 0, "Not Vulnerable": 0}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('original_severity', 'Medium')
            status = vuln.get('final_status', 'Not Vulnerable')
            
            if severity in risk_matrix and status in risk_matrix[severity]:
                risk_matrix[severity][status] += 1
        
        return risk_matrix
    
    def _generate_next_steps(self, triage_result: Dict) -> List[str]:
        """Generate recommended next steps in the specified language"""
        vulnerable_count = triage_result.get('triage_summary', {}).get('confirmed_vulnerable', 0)
        
        # Language-specific next steps
        steps_templates = {
            "en": {
                "vulnerable": [
                    "Immediately address all confirmed vulnerable findings",
                    "Prioritize remediation based on risk rating and exploitability",
                    "Implement security patches and code fixes",
                    "Conduct verification testing after remediation"
                ],
                "general": [
                    "Review and implement security recommendations",
                    "Establish regular security testing procedures",
                    "Consider implementing additional security controls",
                    "Schedule follow-up security assessments"
                ]
            },
            "es": {
                "vulnerable": [
                    "Abordar inmediatamente todos los hallazgos vulnerables confirmados",
                    "Priorizar la remediación basada en la calificación de riesgo y explotabilidad",
                    "Implementar parches de seguridad y correcciones de código",
                    "Realizar pruebas de verificación después de la remediación"
                ],
                "general": [
                    "Revisar e implementar las recomendaciones de seguridad",
                    "Establecer procedimientos regulares de pruebas de seguridad",
                    "Considerar implementar controles de seguridad adicionales",
                    "Programar evaluaciones de seguridad de seguimiento"
                ]
            }
        }
        
        template = steps_templates.get(self.language, steps_templates["en"])
        next_steps = []
        
        if vulnerable_count > 0:
            next_steps.extend(template["vulnerable"])
        
        next_steps.extend(template["general"])
        
        return next_steps