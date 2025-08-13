from crewai import Agent
from langchain_openai import ChatOpenAI
from typing import Dict, Any, List

from ..tools.pdf_tools import PDFReaderTool
from ..tools.database_tools import DatabaseUpdateTool, DatabaseCreateTool, DatabaseQueryTool
import logging

logger = logging.getLogger(__name__)

class ReaderAgent:
    """Agent responsible for reading and interpreting vulnerability reports from PDF"""
    
    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.pdf_tool = PDFReaderTool()
        self.db_update_tool = DatabaseUpdateTool()
        self.db_create_tool = DatabaseCreateTool()
        self.db_query_tool = DatabaseQueryTool()
        self.agent = self._create_agent()
    
    def _create_agent(self) -> Agent:
        """Create the reader agent with ReAct methodology"""
        return Agent(
            role="Vulnerability Report Reader",
            goal="Extract, interpret and structure vulnerability information from PDF reports",
            backstory="""
            You are an expert cybersecurity analyst specialized in reading and interpreting 
            vulnerability reports. You follow the ReAct methodology (Reasoning and Action) 
            to systematically extract and organize vulnerability information.
            
            Your process:
            1. REASON: Analyze the PDF structure and content
            2. ACT: Extract text using PDF tools
            3. REASON: Interpret and categorize vulnerabilities
            4. ACT: Structure the information in a standardized format
            
            You excel at:
            - Identifying vulnerability types (XSS, SQLi, CSRF, etc.)
            - Extracting severity levels and CVSS scores
            - Understanding proof-of-concept exploits
            - Organizing findings by priority and impact
            """,
            verbose=True,
            allow_delegation=False,
            tools=[self.pdf_tool, self.db_update_tool, self.db_create_tool, self.db_query_tool],
            llm=self.llm,
            max_iter=5,
            memory=True
        )
    
    def process_report(self, pdf_path: str, db_manager=None, document_id=None) -> Dict[str, Any]:
        """Process a vulnerability report PDF with incremental database updates"""
        logger.info(f"Processing PDF report: {pdf_path}")
        
        try:
            # Extract text from PDF
            raw_text = self.pdf_tool.extract_text(pdf_path)
            
            # Update database with initial PDF processing status
            if db_manager and document_id:
                initial_data = {
                    "status": "processing_pdf",
                    "pdf_extracted": True,
                    "text_length": len(raw_text)
                }
                db_manager.update_assessment_stage(document_id, 'pdf_analysis', initial_data)
                logger.info("Database updated: PDF text extracted")
            
            # Use LLM to interpret and structure the content
            prompt = f"""
            As a vulnerability report reader following ReAct methodology, analyze this PDF content:
            
            REASONING: I need to extract and structure vulnerability information from this report.
            
            Raw PDF Content:
            {raw_text[:10000]}  # Limit to first 10k chars to avoid token limits
            
            ACTION: Extract and organize the following information:
            
            1. Report metadata (title, date, target application, etc.)
            2. Executive summary
            3. List of vulnerabilities with:
               - Vulnerability name/title
               - Type/category (XSS, SQLi, etc.)
               - Severity level
               - CVSS score (if available)
               - Affected endpoints/components
               - Description
               - Proof of concept/exploit details
               - Remediation recommendations
            
            REASONING: I should structure this as JSON for easy processing by other agents.
            
            Provide the result as a structured JSON object with the following format:
            {{
                "report_metadata": {{
                    "title": "string",
                    "date": "string",
                    "target": "string",
                    "total_vulnerabilities": "number"
                }},
                "executive_summary": "string",
                "vulnerabilities": [
                    {{
                        "id": "string",
                        "title": "string",
                        "type": "string",
                        "severity": "string",
                        "cvss_score": "string",
                        "affected_components": ["string"],
                        "description": "string",
                        "proof_of_concept": "string",
                        "remediation": "string",
                        "status": "Pending Validation"
                    }}
                ]
            }}
            """
            
            response = self.llm.invoke(prompt)
            
            # Parse the response and extract JSON
            import json
            import re
            
            # Try to extract JSON from the response
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                try:
                    structured_data = json.loads(json_match.group())
                    vulnerabilities = structured_data.get('vulnerabilities', [])
                    logger.info(f"Successfully parsed {len(vulnerabilities)} vulnerabilities")
                    
                    # Update database with found vulnerabilities immediately
                    if db_manager and document_id and vulnerabilities:
                        vuln_data = {
                            "status": "vulnerabilities_found",
                            "vulnerabilities": vulnerabilities,
                            "total_vulnerabilities": len(vulnerabilities),
                            "report_metadata": structured_data.get('report_metadata', {})
                        }
                        db_manager.update_assessment_stage(document_id, 'pdf_analysis', vuln_data)
                        logger.info(f"Database updated: Found {len(vulnerabilities)} vulnerabilities from PDF")
                    
                    return structured_data
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON: {e}")
                    return self._create_fallback_structure(raw_text)
            else:
                logger.warning("No JSON found in response, creating fallback structure")
                return self._create_fallback_structure(raw_text)
                
        except Exception as e:
            logger.error(f"Error processing PDF: {e}")
            raise
    
    def _create_fallback_structure(self, raw_text: str) -> Dict[str, Any]:
        """Create a fallback structure when JSON parsing fails"""
        return {
            "report_metadata": {
                "title": "Unknown Report",
                "date": "Unknown",
                "target": "Unknown",
                "total_vulnerabilities": 0
            },
            "executive_summary": "Failed to parse report structure. Raw content available.",
            "vulnerabilities": [],
            "raw_content": raw_text[:5000],  # Store first 5k chars as fallback
            "parsing_error": True
        }