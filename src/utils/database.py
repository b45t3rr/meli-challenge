import os
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import logging

logger = logging.getLogger(__name__)

def serialize_for_mongodb(obj):
    """Recursively serialize objects for MongoDB storage"""
    if hasattr(obj, '__dict__'):
        # Handle CrewOutput and other objects with attributes
        result = {}
        for key, value in obj.__dict__.items():
            if not key.startswith('_'):  # Skip private attributes
                result[key] = serialize_for_mongodb(value)
        return result
    elif hasattr(obj, 'raw') and hasattr(obj, 'pydantic_output'):
        # Handle CrewOutput specifically
        return {
            'raw': str(obj.raw) if obj.raw else None,
            'pydantic_output': serialize_for_mongodb(obj.pydantic_output) if obj.pydantic_output else None,
            'json_dict': obj.json_dict if hasattr(obj, 'json_dict') else None,
            'tasks_output': [serialize_for_mongodb(task) for task in obj.tasks_output] if hasattr(obj, 'tasks_output') else None,
            'token_usage': serialize_for_mongodb(obj.token_usage) if hasattr(obj, 'token_usage') else None
        }
    elif isinstance(obj, (list, tuple)):
        return [serialize_for_mongodb(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: serialize_for_mongodb(value) for key, value in obj.items()}
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, '__str__') and not isinstance(obj, (str, int, float, bool, type(None))):
        # Convert complex objects to string representation
        return str(obj)
    else:
        return obj

class DatabaseManager:
    """MongoDB database manager for storing vulnerability assessment results"""
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize database connection
        
        Args:
            connection_string: MongoDB connection string. If None, constructs from environment variables
                             or defaults to localhost
        """
        if connection_string:
            self.connection_string = connection_string
        else:
            # Try to get from MONGODB_URI first
            self.connection_string = os.getenv('MONGODB_URI')
            
            # If not found, construct from individual environment variables
            if not self.connection_string:
                mongo_host = os.getenv('MONGO_HOST', 'localhost')
                mongo_port = os.getenv('MONGO_PORT', '27017')
                mongo_username = os.getenv('MONGO_USERNAME')
                mongo_password = os.getenv('MONGO_PASSWORD')
                mongo_auth_source = os.getenv('MONGO_AUTH_SOURCE', 'admin')
                
                if mongo_username and mongo_password:
                    self.connection_string = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/?authSource={mongo_auth_source}"
                else:
                    self.connection_string = f"mongodb://{mongo_host}:{mongo_port}/"
        
        self.client = None
        self.db = None
        self.collection = None
        
    def connect(self, database_name: str = None, 
                collection_name: str = None) -> bool:
        """
        Connect to MongoDB database
        
        Args:
            database_name: Name of the database (defaults to env var or 'vulnerability_validation')
            collection_name: Name of the collection (defaults to env var or 'assessments')
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        # Use environment variables or defaults
        database_name = database_name or os.getenv('MONGO_DATABASE', 'vulnerability_validation')
        collection_name = collection_name or os.getenv('COLLECTION_NAME', 'assessments')
        try:
            self.client = MongoClient(
                self.connection_string,
                serverSelectionTimeoutMS=5000  # 5 second timeout
            )
            
            # Test connection
            self.client.admin.command('ping')
            
            self.db = self.client[database_name]
            self.collection = self.db[collection_name]
            
            logger.info(f"Successfully connected to MongoDB: {database_name}.{collection_name}")
            return True
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            return False
    
    def save_assessment_result(self, result: Dict[str, Any], 
                             pdf_path: str = None,
                             source_path: str = None,
                             target_url: str = None,
                             model_used: str = None,
                             execution_mode: str = None) -> Optional[str]:
        """
        Save vulnerability assessment result to database
        
        Args:
            result: Assessment result dictionary
            pdf_path: Path to the PDF report
            source_path: Path to source code
            target_url: Target URL for dynamic testing
            model_used: LLM model used for analysis
            execution_mode: Execution mode (full, reader-only, static-only, dynamic-only)
            
        Returns:
            str: Document ID if successful, None otherwise
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return None
            
        try:
            # Serialize the result to ensure MongoDB compatibility
            serialized_result = serialize_for_mongodb(result)
            
            # Prepare document with metadata
            document = {
                'timestamp': datetime.utcnow(),
                'execution_metadata': {
                    'pdf_path': pdf_path,
                    'source_path': source_path,
                    'target_url': target_url,
                    'model_used': model_used,
                    'execution_mode': execution_mode
                },
                'assessment_result': serialized_result,
                'version': '1.0'
            }
            
            # Insert document
            insert_result = self.collection.insert_one(document)
            document_id = str(insert_result.inserted_id)
            
            logger.info(f"Assessment result saved to database with ID: {document_id}")
            return document_id
            
        except Exception as e:
            logger.error(f"Failed to save assessment result: {e}")
            return None
    
    def save_triage_result(self, triage_result: Dict[str, Any], 
                          pdf_path: str = None,
                          source_path: str = None,
                          target_url: str = None,
                          model_used: str = None,
                          execution_mode: str = None) -> Optional[str]:
        """
        Save only the triage analysis result to database
        
        Args:
            triage_result: Triage analysis result dictionary
            pdf_path: Path to the PDF report
            source_path: Path to source code
            target_url: Target URL for dynamic testing
            model_used: LLM model used for analysis
            execution_mode: Execution mode
            
        Returns:
            str: Document ID if successful, None otherwise
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return None
            
        try:
            # Serialize the triage result to ensure MongoDB compatibility
            serialized_triage = serialize_for_mongodb(triage_result)
            
            # Prepare document with metadata
            document = {
                'timestamp': datetime.utcnow(),
                'document_type': 'triage_analysis',
                'execution_metadata': {
                    'pdf_path': pdf_path,
                    'source_path': source_path,
                    'target_url': target_url,
                    'model_used': model_used,
                    'execution_mode': execution_mode
                },
                'triage_result': serialized_triage,
                'version': '1.0'
            }
            
            # Insert document
            insert_result = self.collection.insert_one(document)
            document_id = str(insert_result.inserted_id)
            
            logger.info(f"Triage result saved to database with ID: {document_id}")
            return document_id
            
        except Exception as e:
            logger.error(f"Failed to save triage result: {e}")
            return None
    
    def get_assessment_by_id(self, document_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve assessment result by document ID
        
        Args:
            document_id: MongoDB document ID
            
        Returns:
            dict: Assessment document if found, None otherwise
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return None
            
        try:
            from bson import ObjectId
            result = self.collection.find_one({'_id': ObjectId(document_id)})
            return result
        except Exception as e:
            logger.error(f"Failed to retrieve assessment: {e}")
            return None
    
    def get_recent_assessments(self, limit: int = 10) -> list:
        """
        Get recent assessment results
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            list: List of recent assessment documents
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return []
            
        try:
            results = list(
                self.collection.find()
                .sort('timestamp', -1)
                .limit(limit)
            )
            return results
        except Exception as e:
            logger.error(f"Failed to retrieve recent assessments: {e}")
            return []
    
    def search_assessments(self, query: Dict[str, Any]) -> list:
        """
        Search assessments by query
        
        Args:
            query: MongoDB query dictionary
            
        Returns:
            list: List of matching assessment documents
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return []
            
        try:
            results = list(self.collection.find(query))
            return results
        except Exception as e:
            logger.error(f"Failed to search assessments: {e}")
            return []
    
    def get_triage_results(self, limit: int = 10) -> list:
        """
        Get recent triage analysis results
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            list: List of recent triage analysis documents
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return []
            
        try:
            results = list(
                self.collection.find({'document_type': 'triage_analysis'})
                .sort('timestamp', -1)
                .limit(limit)
            )
            return results
        except Exception as e:
            logger.error(f"Failed to retrieve triage results: {e}")
            return []
    
    def get_triage_by_id(self, document_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve triage analysis result by document ID
        
        Args:
            document_id: MongoDB document ID
            
        Returns:
            dict: Triage analysis document if found, None otherwise
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return None
            
        try:
            from bson import ObjectId
            result = self.collection.find_one({
                '_id': ObjectId(document_id),
                'document_type': 'triage_analysis'
            })
            return result
        except Exception as e:
            logger.error(f"Failed to retrieve triage analysis: {e}")
            return None
    
    def close_connection(self):
        """Close database connection"""
        if self.client:
            self.client.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close_connection()

def save_result_to_file(result: Dict[str, Any], output_path: str) -> bool:
    """
    Save assessment result to JSON file as backup
    
    Args:
        result: Assessment result dictionary
        output_path: Path to output JSON file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Serialize the result to ensure JSON compatibility
        serialized_result = serialize_for_mongodb(result)
        
        # Add timestamp to result
        result_with_timestamp = {
            'timestamp': datetime.utcnow().isoformat(),
            'result': serialized_result
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_with_timestamp, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"Assessment result saved to file: {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to save result to file: {e}")
        return False

def initialize_database() -> DatabaseManager:
    """
    Initialize and test database connection
    
    Returns:
        DatabaseManager: Configured database manager
    """
    db_manager = DatabaseManager()
    
    if db_manager.connect():
        logger.info("Database initialized successfully")
    else:
        logger.warning("Database connection failed. Results will only be saved to file.")
    
    return db_manager