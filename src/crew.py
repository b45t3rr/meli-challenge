from crewai import Crew, Process
from crewai.project import CrewBase, agent, crew, task
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from typing import Dict, Any, Optional, Union
import os

from .agents.reader_agent import ReaderAgent
from .agents.static_agent import StaticAgent
from .agents.dynamic_agent import DynamicAgent
from .agents.triage_agent import TriageAgent
from .tasks.vulnerability_tasks import VulnerabilityTasks
import logging

logger = logging.getLogger(__name__)

class VulnerabilityValidationCrew:
    """Main crew orchestrator for vulnerability validation"""
    
    def __init__(self, model: str = "gpt-4o-mini", verbose: bool = False, language: str = "en"):
        self.model = model
        self.verbose = verbose
        self.language = language
        self.llm = self._setup_llm()
        
        # Initialize agents
        self.reader_agent = ReaderAgent(llm=self.llm)
        self.static_agent = StaticAgent(llm=self.llm)
        self.dynamic_agent = DynamicAgent(llm=self.llm)
        self.triage_agent = TriageAgent(llm=self.llm, language=self.language)
        
        # Initialize tasks
        self.tasks = VulnerabilityTasks()
    
    def _setup_llm(self) -> Union[ChatOpenAI, ChatAnthropic, ChatGoogleGenerativeAI]:
        """Setup the language model based on the specified model"""
        
        # Handle different model providers
        if self.model.startswith('deepseek'):
            api_key = os.getenv('DEEPSEEK_API_KEY')
            if not api_key:
                raise ValueError("DEEPSEEK_API_KEY environment variable is required for DeepSeek models")
            base_url = os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')
            # Use the correct format for litellm
            model_name = f"deepseek/{self.model}"
            return ChatOpenAI(
                model=model_name,
                api_key=api_key,
                base_url=base_url,
                temperature=0.1
            )
        elif self.model.startswith('grok-') or 'xai' in self.model.lower():
            api_key = os.getenv('XAI_API_KEY')
            if not api_key:
                raise ValueError("XAI_API_KEY environment variable is required for xAI models")
            base_url = os.getenv('XAI_BASE_URL', 'https://api.x.ai/v1')
            # Use the correct format for litellm
            model_name = f"xai/{self.model}"
            return ChatOpenAI(
                model=model_name,
                api_key=api_key,
                base_url=base_url,
                temperature=0.1
            )
        elif self.model.startswith('claude-') or 'anthropic' in self.model.lower():
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY environment variable is required for Anthropic models")
            return ChatAnthropic(
                model=self.model,
                api_key=api_key,
                temperature=0.1
            )
        elif self.model.startswith('gemini-') or 'google' in self.model.lower():
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                raise ValueError("GEMINI_API_KEY environment variable is required for Gemini models")
            return ChatGoogleGenerativeAI(
                model=self.model,
                google_api_key=api_key,
                temperature=0.1
            )
        else:
            # Default to OpenAI
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OPENAI_API_KEY environment variable is required for OpenAI models")
            return ChatOpenAI(
                model=self.model,
                api_key=api_key,
                temperature=0.1
            )
    
    def execute(self, pdf_path: str, source_path: str, target_url: str, mode: str = "full") -> Dict[str, Any]:
        """Execute the vulnerability validation process"""
        logger.info(f"Starting vulnerability validation in {mode} mode")
        
        try:
            if mode == "reader":
                return self._execute_reader_only(pdf_path)
            elif mode == "static":
                return self._execute_static_only(source_path)
            elif mode == "dynamic":
                return self._execute_dynamic_only(target_url)
            else:
                return self._execute_full_analysis(pdf_path, source_path, target_url)
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            raise
    
    def _execute_reader_only(self, pdf_path: str) -> Dict[str, Any]:
        """Execute only the reader agent"""
        logger.info("Executing reader-only analysis")
        
        # Create crew with only reader agent
        crew = Crew(
            agents=[self.reader_agent.agent],
            tasks=[self.tasks.create_read_task(self.reader_agent.agent, pdf_path)],
            process=Process.sequential,
            verbose=self.verbose
        )
        
        result = crew.kickoff()
        return {
            "mode": "reader",
            "pdf_analysis": result,
            "timestamp": self._get_timestamp()
        }
    
    def _execute_static_only(self, source_path: str) -> Dict[str, Any]:
        """Execute only the static analysis agent"""
        logger.info("Executing static-only analysis")
        
        crew = Crew(
            agents=[self.static_agent.agent],
            tasks=[self.tasks.create_static_task(self.static_agent.agent, source_path)],
            process=Process.sequential,
            verbose=self.verbose
        )
        
        result = crew.kickoff()
        return {
            "mode": "static",
            "static_analysis": result,
            "timestamp": self._get_timestamp()
        }
    
    def _execute_dynamic_only(self, target_url: str) -> Dict[str, Any]:
        """Execute only the dynamic analysis agent"""
        logger.info("Executing dynamic-only analysis")
        
        crew = Crew(
            agents=[self.dynamic_agent.agent],
            tasks=[self.tasks.create_dynamic_task(self.dynamic_agent.agent, target_url)],
            process=Process.sequential,
            verbose=self.verbose
        )
        
        result = crew.kickoff()
        return {
            "mode": "dynamic",
            "dynamic_analysis": result,
            "timestamp": self._get_timestamp()
        }
    
    def _execute_full_analysis(self, pdf_path: str, source_path: str, target_url: str) -> Dict[str, Any]:
        """Execute full analysis with all agents"""
        logger.info("Executing full analysis with all agents")
        
        # Create all tasks
        read_task = self.tasks.create_read_task(self.reader_agent.agent, pdf_path)
        static_task = self.tasks.create_static_task(self.static_agent.agent, source_path)
        dynamic_task = self.tasks.create_dynamic_task(self.dynamic_agent.agent, target_url)
        triage_task = self.tasks.create_triage_task(
            self.triage_agent.agent,
            [read_task, static_task, dynamic_task],
            language=self.language
        )
        
        # Set task dependencies
        static_task.context = [read_task]
        dynamic_task.context = [read_task]
        triage_task.context = [read_task, static_task, dynamic_task]
        
        # Create crew
        crew = Crew(
            agents=[
                self.reader_agent.agent,
                self.static_agent.agent,
                self.dynamic_agent.agent,
                self.triage_agent.agent
            ],
            tasks=[read_task, static_task, dynamic_task, triage_task],
            process=Process.sequential,
            verbose=self.verbose
        )
        
        result = crew.kickoff()
        
        # Extract individual agent results from crew output
        pdf_analysis = None
        static_analysis = None
        dynamic_analysis = None
        
        if hasattr(result, 'tasks_output') and result.tasks_output:
            for i, task_output in enumerate(result.tasks_output):
                if i == 0:  # Reader task
                    pdf_analysis = task_output.json_dict if hasattr(task_output, 'json_dict') else str(task_output.raw)
                elif i == 1:  # Static task
                    static_analysis = task_output.json_dict if hasattr(task_output, 'json_dict') else str(task_output.raw)
                elif i == 2:  # Dynamic task
                    dynamic_analysis = task_output.json_dict if hasattr(task_output, 'json_dict') else str(task_output.raw)
        
        # Execute triage agent directly to get structured result
        structured_triage_result = None
        try:
            if pdf_analysis and static_analysis and dynamic_analysis:
                structured_triage_result = self.triage_agent.triage_vulnerabilities(
                    pdf_analysis=pdf_analysis,
                    static_analysis=static_analysis,
                    dynamic_analysis=dynamic_analysis
                )
                logger.info("Successfully executed triage agent directly")
        except Exception as e:
            logger.error(f"Direct triage execution failed: {e}")
        
        # Extract triage results from CrewAI output as fallback
        crew_triage_result = None
        if hasattr(result, 'tasks_output') and result.tasks_output:
            # The triage task is the last one (index 3)
            for task_output in result.tasks_output:
                if hasattr(task_output, 'agent') and 'triage' in str(task_output.agent).lower():
                    crew_triage_result = {
                        'raw_output': str(task_output.raw) if hasattr(task_output, 'raw') else None,
                        'json_dict': task_output.json_dict if hasattr(task_output, 'json_dict') else None,
                        'pydantic_output': task_output.pydantic_output if hasattr(task_output, 'pydantic_output') else None
                    }
                    break
        
        # If triage result not found in tasks_output, try to extract from main result
        if not crew_triage_result and hasattr(result, 'raw'):
            crew_triage_result = {
                'raw_output': str(result.raw),
                'json_dict': result.json_dict if hasattr(result, 'json_dict') else None,
                'pydantic_output': result.pydantic_output if hasattr(result, 'pydantic_output') else None
            }
        
        # Extract vulnerabilities from structured triage result for main access
        vulnerabilities = []
        if structured_triage_result and 'vulnerability_triage' in structured_triage_result:
            vulnerabilities = structured_triage_result['vulnerability_triage']
        
        return {
            "mode": "full",
            "final_result": result,
            "triage_analysis": crew_triage_result,
            "structured_triage_result": structured_triage_result,  # This contains the vulnerabilities with technical evidence
            "vulnerabilities": vulnerabilities,  # Main vulnerabilities field with technical evidence
            "pdf_analysis": pdf_analysis,
            "static_analysis": static_analysis,
            "dynamic_analysis": dynamic_analysis,
            "timestamp": self._get_timestamp(),
            "pdf_path": pdf_path,
            "source_path": source_path,
            "target_url": target_url
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()