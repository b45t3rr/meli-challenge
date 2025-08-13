import os
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class AppConfig:
    """Application configuration settings"""
    
    # LLM Configuration
    default_model: str = "gpt-4o-mini"
    openai_api_key: Optional[str] = None
    deepseek_api_key: Optional[str] = None
    xai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    
    # Database Configuration
    mongodb_uri: str = "mongodb://localhost:27017/"
    database_name: str = "vulnerability_validation"
    collection_name: str = "assessments"
    
    # Tool Configuration
    semgrep_timeout: int = 300  # 5 minutes
    network_timeout: int = 30   # 30 seconds
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    
    # Logging Configuration
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    def __post_init__(self):
        """Load configuration from environment variables"""
        self.openai_api_key = os.getenv('OPENAI_API_KEY', self.openai_api_key)
        self.deepseek_api_key = os.getenv('DEEPSEEK_API_KEY', self.deepseek_api_key)
        self.xai_api_key = os.getenv('XAI_API_KEY', self.xai_api_key)
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY', self.anthropic_api_key)
        self.gemini_api_key = os.getenv('GEMINI_API_KEY', self.gemini_api_key)
        self.mongodb_uri = os.getenv('MONGODB_URI', self.mongodb_uri)
        self.log_level = os.getenv('LOG_LEVEL', self.log_level)
    
    def get_model_config(self, model_name: str) -> Dict[str, Any]:
        """Get model configuration based on model name"""
        if model_name.startswith('gpt-') or model_name.startswith('o1-'):
            return {
                'provider': 'openai',
                'api_key': self.openai_api_key,
                'model': model_name
            }
        elif 'deepseek' in model_name.lower():
            return {
                'provider': 'deepseek',
                'api_key': self.deepseek_api_key,
                'model': model_name,
                'base_url': 'https://api.deepseek.com'
            }
        elif model_name.startswith('grok-') or 'xai' in model_name.lower():
            return {
                'provider': 'xai',
                'api_key': self.xai_api_key,
                'model': model_name,
                'base_url': 'https://api.x.ai/v1'
            }
        elif model_name.startswith('claude-') or 'anthropic' in model_name.lower():
            return {
                'provider': 'anthropic',
                'api_key': self.anthropic_api_key,
                'model': model_name
            }
        elif model_name.startswith('gemini-') or 'google' in model_name.lower():
            return {
                'provider': 'gemini',
                'api_key': self.gemini_api_key,
                'model': model_name
            }
        else:
            # Default to OpenAI for unknown models
            return {
                'provider': 'openai',
                'api_key': self.openai_api_key,
                'model': model_name
            }
    
    def validate_config(self) -> bool:
        """Validate configuration settings"""
        errors = []
        
        # Check API keys
        if not any([self.openai_api_key, self.deepseek_api_key, self.xai_api_key, 
                   self.anthropic_api_key, self.gemini_api_key]):
            errors.append("No API keys configured. Set at least one of: OPENAI_API_KEY, DEEPSEEK_API_KEY, XAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY environment variable.")
        
        # Check MongoDB URI format
        if not self.mongodb_uri.startswith(('mongodb://', 'mongodb+srv://')):
            errors.append("Invalid MongoDB URI format.")
        
        if errors:
            for error in errors:
                logging.error(f"Configuration error: {error}")
            return False
        
        return True

def setup_logging(config: AppConfig) -> None:
    """Setup application logging"""
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper()),
        format=config.log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('vulnerability_validation.log')
        ]
    )
    
    # Set specific loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('pymongo').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.info("Logging configured successfully")

def load_config() -> AppConfig:
    """Load application configuration"""
    config = AppConfig()
    
    # Setup logging first
    setup_logging(config)
    
    logger = logging.getLogger(__name__)
    logger.info("Configuration loaded")
    
    # Validate configuration
    if not config.validate_config():
        logger.warning("Configuration validation failed. Some features may not work properly.")
    
    return config

# Global configuration instance
config = load_config()