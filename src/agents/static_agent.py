from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List
import json
import subprocess
import os

from ..tools.file_tools import FileReaderTool, SemgrepTool
import logging

logger = logging.getLogger(__name__)

class StaticAgent:
    """Agent responsible for static code analysis using Semgrep"""
    
    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.file_tool = FileReaderTool()
        self.semgrep_tool = SemgrepTool()
        self.agent = self._create_agent()
    
    def _create_agent(self) -> Agent:
        """Create the static analysis agent with ReAct methodology"""
        return Agent(
            role="Static Code Analysis Expert",
            goal="Perform comprehensive static analysis to validate vulnerabilities using Semgrep and code inspection",
            backstory="""
            You are a senior security engineer specialized in static code analysis. You follow 
            the ReAct methodology (Reasoning and Action) to systematically analyze source code 
            for security vulnerabilities.
            
            Your process:
            1. REASON: Analyze the vulnerability report to understand what to look for
            2. ACT: Run Semgrep scans on the source code using 'auto' configuration
            3. REASON: Interpret Semgrep results and correlate with reported vulnerabilities
            4. ACT: Investigate specific code files for deeper analysis
            5. REASON: Determine vulnerability status based on evidence
            
            You excel at:
            - Running and interpreting Semgrep security scans
            - Reading and analyzing source code for vulnerabilities
            - Correlating static analysis results with vulnerability reports
            - Determining if vulnerabilities are exploitable in the current codebase
            - Assigning accurate vulnerability statuses: Vulnerable, Possible, Not Vulnerable
            """,
            verbose=True,
            allow_delegation=False,
            tools=[self.file_tool, self.semgrep_tool],
            llm=self.llm,
            max_iter=10,
            memory=True
        )
    
    def analyze_code(self, source_path: str, vulnerabilities: List[Dict] = None) -> Dict[str, Any]:
        """Perform static analysis on the source code"""
        logger.info(f"Starting static analysis on: {source_path}")
        
        try:
            # Step 1: Run Semgrep scan
            semgrep_results = self._run_semgrep_scan(source_path)
            
            # Step 2: Analyze results with LLM
            analysis_result = self._analyze_with_llm(semgrep_results, vulnerabilities, source_path)
            
            return {
                "semgrep_results": semgrep_results,
                "vulnerability_analysis": analysis_result,
                "source_path": source_path
            }
            
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            raise
    
    def _run_semgrep_scan(self, source_path: str) -> Dict[str, Any]:
        """Run Semgrep security scan on the source code"""
        logger.info("Running Semgrep security scan...")
        
        try:
            # Run Semgrep with security rules
            cmd = [
                "semgrep",
                "--config=auto",  # Use automatic rule selection
                "--json",
                "--no-git-ignore",
                "--max-target-bytes=1000000",  # Limit file size to avoid huge files
                source_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0 or result.returncode == 1:  # 1 means findings found
                try:
                    semgrep_output = json.loads(result.stdout)
                    logger.info(f"Semgrep found {len(semgrep_output.get('results', []))} potential issues")
                    return semgrep_output
                except json.JSONDecodeError:
                    logger.error("Failed to parse Semgrep JSON output")
                    return {"results": [], "errors": ["Failed to parse Semgrep output"]}
            else:
                logger.error(f"Semgrep failed with return code {result.returncode}")
                logger.error(f"Stderr: {result.stderr}")
                return {"results": [], "errors": [f"Semgrep execution failed: {result.stderr}"]}
                
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return {"results": [], "errors": ["Semgrep scan timed out"]}
        except FileNotFoundError:
            logger.error("Semgrep not found. Please install semgrep.")
            return {"results": [], "errors": ["Semgrep not installed"]}
        except Exception as e:
            logger.error(f"Unexpected error running Semgrep: {e}")
            return {"results": [], "errors": [f"Unexpected error: {str(e)}"]}
    
    def _analyze_with_llm(self, semgrep_results: Dict, vulnerabilities: List[Dict], source_path: str) -> Dict[str, Any]:
        """Analyze Semgrep results using LLM with ReAct methodology"""
        
        # Prepare vulnerability context
        vuln_context = ""
        if vulnerabilities:
            vuln_context = "\n".join([
                f"- {v.get('title', 'Unknown')}: {v.get('type', 'Unknown')} in {v.get('affected_components', [])}"
                for v in vulnerabilities
            ])
        
        # Prepare Semgrep findings summary
        semgrep_summary = ""
        if semgrep_results.get('results'):
            semgrep_summary = "\n".join([
                f"- {r.get('check_id', 'Unknown')}: {r.get('message', 'No message')} in {r.get('path', 'Unknown')}"
                for r in semgrep_results['results'][:20]  # Limit to first 20 results
            ])
        
        prompt = f"""
        As a static code analysis expert following ReAct methodology, analyze these Semgrep results:
        
        REASONING: I need to correlate Semgrep findings with reported vulnerabilities and investigate specific code areas.
        
        REPORTED VULNERABILITIES:
        {vuln_context or "No specific vulnerabilities provided"}
        
        SEMGREP FINDINGS:
        {semgrep_summary or "No Semgrep findings"}
        
        ACTION: For each reported vulnerability, I will:
        1. Check if Semgrep detected similar issues
        2. Investigate specific code files if needed
        3. Determine the vulnerability status
        
        REASONING: I should examine the findings first and correlate them with the vulnerability report.

        IMPORTANT: I must only respond with the vulnerabilities reported in the vulnerability report, any other finding must be discarded.
        
        Please provide analysis in this JSON format:
        {{
            "analysis_summary": "Overall assessment of the static analysis",
            "vulnerability_assessments": [
                {{
                    "vulnerability_id": "string",
                    "static_status": "Vulnerable|Possible|Not Vulnerable",
                    "evidence": "Description of evidence found or not found",
                    "semgrep_matches": ["List of relevant Semgrep findings"],
                    "code_locations": ["Specific files/lines that need attention"],
                    "confidence": "High|Medium|Low",
                    "reasoning": "Detailed reasoning for the assessment"
                }}
            ],
            "additional_findings": [
                {{
                    "type": "string",
                    "description": "string",
                    "severity": "string",
                    "location": "string"
                }}
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
                    analysis_data = json.loads(json_match.group())
                    
                    # If we have specific vulnerabilities, investigate code files
                    if vulnerabilities:
                        analysis_data = self._investigate_specific_files(analysis_data, vulnerabilities, source_path)
                    
                    return analysis_data
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse LLM analysis JSON: {e}")
                    return self._create_fallback_analysis(semgrep_results)
            else:
                logger.warning("No JSON found in LLM response")
                return self._create_fallback_analysis(semgrep_results)
                
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._create_fallback_analysis(semgrep_results)
    
    def _investigate_specific_files(self, analysis_data: Dict, vulnerabilities: List[Dict], source_path: str) -> Dict:
        """Investigate specific files mentioned in vulnerabilities"""
        logger.info("Investigating specific code files...")
        
        for vuln in vulnerabilities:
            affected_components = vuln.get('affected_components', [])
            
            for component in affected_components:
                # Try to find and read relevant files
                potential_files = self._find_relevant_files(component, source_path)
                
                for file_path in potential_files[:3]:  # Limit to 3 files per component
                    try:
                        file_content = self.file_tool.read_file(file_path)
                        
                        # Analyze file content for the specific vulnerability
                        file_analysis = self._analyze_file_content(file_content, vuln, file_path)
                        
                        # Update analysis data with file-specific findings
                        for assessment in analysis_data.get('vulnerability_assessments', []):
                            if assessment.get('vulnerability_id') == vuln.get('id'):
                                assessment['code_locations'].append(f"{file_path}: {file_analysis}")
                                break
                                
                    except Exception as e:
                        logger.warning(f"Could not analyze file {file_path}: {e}")
        
        return analysis_data
    
    def _find_relevant_files(self, component: str, source_path: str) -> List[str]:
        """Find files that might be related to the affected component"""
        relevant_files = []
        
        try:
            # Walk through source directory
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    if file.endswith(('.py', '.js', '.php', '.java', '.cs', '.rb', '.go')):
                        file_path = os.path.join(root, file)
                        
                        # Check if component name is in file path or name
                        if component.lower() in file.lower() or component.lower() in file_path.lower():
                            relevant_files.append(file_path)
                            
                        if len(relevant_files) >= 10:  # Limit search
                            break
                            
        except Exception as e:
            logger.warning(f"Error finding relevant files: {e}")
        
        return relevant_files
    
    def _analyze_file_content(self, content: str, vulnerability: Dict, file_path: str) -> str:
        """Analyze specific file content for vulnerability patterns"""
        vuln_type = vulnerability.get('type', '').lower()
        
        # Simple pattern matching based on vulnerability type
        patterns = {
            'xss': ['innerHTML', 'document.write', 'eval(', 'dangerouslySetInnerHTML'],
            'sql': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'query(', 'execute('],
            'csrf': ['@csrf_exempt', 'csrf_token', 'X-CSRFToken'],
            'lfi': ['include(', 'require(', 'file_get_contents', 'readfile'],
            'rce': ['exec(', 'system(', 'shell_exec', 'eval(', 'subprocess']
        }
        
        findings = []
        for pattern_type, pattern_list in patterns.items():
            if pattern_type in vuln_type:
                for pattern in pattern_list:
                    if pattern in content:
                        findings.append(f"Found {pattern} pattern")
        
        return "; ".join(findings) if findings else "No obvious patterns found"
    
    def _create_fallback_analysis(self, semgrep_results: Dict) -> Dict[str, Any]:
        """Create fallback analysis when LLM parsing fails"""
        return {
            "analysis_summary": "Static analysis completed with limited interpretation",
            "vulnerability_assessments": [],
            "additional_findings": [
                {
                    "type": "Semgrep Finding",
                    "description": f"Found {len(semgrep_results.get('results', []))} potential issues",
                    "severity": "Unknown",
                    "location": "Various files"
                }
            ],
            "parsing_error": True,
            "raw_semgrep_results": semgrep_results
        }