import os
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
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
                mongo_username = os.getenv('MONGO_USERNAME', 'admin')
                mongo_password = os.getenv('MONGO_PASSWORD', 'password123')
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
    
    def create_assessment_document(self, 
                                 pdf_path: str = None,
                                 source_path: str = None,
                                 target_url: str = None,
                                 model_used: str = None,
                                 execution_mode: str = None) -> Optional[str]:
        """
        Create initial assessment document with new unified schema
        
        Args:
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
            # Prepare initial document with new unified schema
            document = {
                # MongoDB auto-generates _id
                'timestamp': datetime.utcnow(),
                'status': 'in_progress',  # in_progress, completed, failed
                'progress_tracking': {
                    'current_stage': 'initializing',  # initializing, pdf_analysis, static_analysis, dynamic_analysis, triage_analysis, completed
                    'completion_percentage': 0,
                    'stages_completed': [],
                    'estimated_completion': None
                },
                'vulnerabilities': [],  # Will be populated by reader agent and enhanced by other agents
                'final_result': None,   # Final triage report
                'last_updated': datetime.utcnow(),
                
                # Metadata for tracking execution context
                'execution_metadata': {
                    'pdf_path': pdf_path,
                    'source_path': source_path,
                    'target_url': target_url,
                    'model_used': model_used,
                    'execution_mode': execution_mode
                },
                
                # Version for schema evolution
                'schema_version': '3.0'
            }
            
            # Insert document
            insert_result = self.collection.insert_one(document)
            document_id = str(insert_result.inserted_id)
            
            logger.info(f"Assessment document created with ID: {document_id}")
            return document_id
            
        except Exception as e:
            logger.error(f"Failed to create assessment document: {e}")
            return None
    
    def update_assessment_stage(self, document_id: str, stage: str, data: Dict[str, Any]) -> bool:
        """
        Update assessment document with data from a specific stage
        
        Args:
            document_id: Document ID to update
            stage: Stage name (pdf_analysis, static_analysis, dynamic_analysis, triage_analysis)
            data: Stage result data
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return False
            
        try:
            from bson import ObjectId
            
            # Serialize the data to ensure MongoDB compatibility
            serialized_data = serialize_for_mongodb(data)
            
            # Get current document to update progress tracking
            doc = self.collection.find_one({'_id': ObjectId(document_id)})
            if not doc:
                logger.warning(f"No document found with ID {document_id}")
                return False
            
            # Update progress tracking
            stages_completed = doc.get('progress_tracking', {}).get('stages_completed', [])
            if stage not in stages_completed:
                stages_completed.append(stage)
            
            total_stages = 4  # pdf, static, dynamic, triage
            completion_percentage = (len(stages_completed) / total_stages) * 100
            
            # Determine next stage
            stage_order = ['pdf_analysis', 'static_analysis', 'dynamic_analysis', 'triage_analysis']
            current_index = stage_order.index(stage) if stage in stage_order else -1
            next_stage = stage_order[current_index + 1] if current_index < len(stage_order) - 1 else 'completed'
            
            # Prepare update data based on stage
            update_data = {
                'progress_tracking.stages_completed': stages_completed,
                'progress_tracking.current_stage': next_stage,
                'progress_tracking.completion_percentage': completion_percentage,
                'status': 'completed' if completion_percentage == 100 else 'in_progress',
                'last_updated': datetime.utcnow()
            }
            
            # Handle stage-specific updates
            if stage == 'pdf_analysis':
                # Reader agent populates vulnerabilities array
                # Check multiple possible locations for vulnerabilities
                vulnerabilities = serialized_data.get('vulnerabilities', [])
                if not vulnerabilities:
                    # Check in result object
                    result_data = serialized_data.get('result', {})
                    if isinstance(result_data, dict):
                        vulnerabilities = result_data.get('vulnerabilities', [])
                if not vulnerabilities:
                    # Check in raw_output if it's JSON
                    raw_output = serialized_data.get('raw_output', '')
                    if isinstance(raw_output, str):
                        try:
                            import json
                            parsed_output = json.loads(raw_output)
                            if isinstance(parsed_output, dict):
                                vulnerabilities = parsed_output.get('vulnerabilities', [])
                        except (json.JSONDecodeError, AttributeError):
                            pass
                if vulnerabilities:
                    update_data['vulnerabilities'] = vulnerabilities
                    
            elif stage in ['static_analysis', 'dynamic_analysis']:
                # Static and dynamic agents enhance existing vulnerabilities with evidence
                current_vulns = doc.get('vulnerabilities', [])
                if current_vulns:  # Only enhance if there are existing vulnerabilities
                    enhanced_vulns = self._enhance_vulnerabilities_with_evidence(current_vulns, serialized_data, stage)
                    update_data['vulnerabilities'] = enhanced_vulns
                
            elif stage == 'triage_analysis':
                # Triage agent provides final result and may update vulnerabilities
                final_result = serialized_data.get('result', {})
                if not final_result:
                    # Try raw_output if result is empty
                    raw_output = serialized_data.get('raw_output', '')
                    if isinstance(raw_output, str):
                        try:
                            import json
                            parsed_output = json.loads(raw_output)
                            if isinstance(parsed_output, dict):
                                final_result = parsed_output
                        except (json.JSONDecodeError, AttributeError):
                            pass
                
                if final_result:
                    update_data['final_result'] = final_result
                    
                    # Update vulnerabilities with final triage information if available
                    if 'vulnerability_triage' in final_result:
                        current_vulns = doc.get('vulnerabilities', [])
                        if current_vulns:
                            triaged_vulns = self._apply_triage_to_vulnerabilities(current_vulns, final_result['vulnerability_triage'])
                            update_data['vulnerabilities'] = triaged_vulns
            
            update_result = self.collection.update_one(
                {'_id': ObjectId(document_id)},
                {'$set': update_data}
            )
            
            if update_result.modified_count > 0:
                logger.info(f"Stage {stage} updated for document {document_id} ({completion_percentage:.1f}% complete)")
                return True
            else:
                logger.warning(f"No document found with ID {document_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update stage {stage}: {e}")
            return False
    
    def _enhance_vulnerabilities_with_evidence(self, current_vulns: List[Dict], stage_data: Dict, stage: str) -> List[Dict]:
        """
        Enhance existing vulnerabilities with evidence from static or dynamic analysis
        
        Args:
            current_vulns: Current vulnerabilities list
            stage_data: Data from static or dynamic analysis
            stage: Stage name (static_analysis or dynamic_analysis)
            
        Returns:
            Enhanced vulnerabilities list
        """
        enhanced_vulns = current_vulns.copy()
        
        try:
            # Get stage result from multiple possible locations
            stage_result = stage_data.get('result', {})
            if not stage_result:
                # Try raw_output if result is empty
                raw_output = stage_data.get('raw_output', '')
                if isinstance(raw_output, str):
                    try:
                        import json
                        parsed_output = json.loads(raw_output)
                        if isinstance(parsed_output, dict):
                            stage_result = parsed_output
                    except (json.JSONDecodeError, AttributeError):
                        pass
            
            if stage == 'static_analysis':
                # Extract static analysis results
                vulnerability_assessments = stage_result.get('vulnerability_analysis', {}).get('vulnerability_assessments', [])
                
                for vuln in enhanced_vulns:
                    vuln_id = vuln.get('id')
                    # Find matching static analysis result
                    for assessment in vulnerability_assessments:
                        if assessment.get('vulnerability_id') == vuln_id:
                            if 'static_evidence' not in vuln:
                                vuln['static_evidence'] = {}
                            vuln['static_evidence'].update({
                                'status': assessment.get('static_status'),
                                'evidence': assessment.get('evidence'),
                                'file_locations': assessment.get('file_locations', []),
                                'code_snippets': assessment.get('code_snippets', []),
                                'timestamp': datetime.utcnow()
                            })
                            break
                            
            elif stage == 'dynamic_analysis':
                # Extract dynamic analysis results
                vulnerability_tests = stage_result.get('vulnerability_tests', [])
                
                for vuln in enhanced_vulns:
                    vuln_id = vuln.get('id')
                    # Find matching dynamic test result
                    for test in vulnerability_tests:
                        if test.get('vulnerability_id') == vuln_id:
                            if 'dynamic_evidence' not in vuln:
                                vuln['dynamic_evidence'] = {}
                            vuln['dynamic_evidence'].update({
                                'status': test.get('dynamic_status'),
                                'test_attempts': test.get('test_attempts', []),
                                'exploitation_proof': test.get('exploitation_proof'),
                                'http_evidence': test.get('http_evidence', {}),
                                'timestamp': datetime.utcnow()
                            })
                            break
                            
        except Exception as e:
            logger.error(f"Error enhancing vulnerabilities with {stage} evidence: {e}")
            
        return enhanced_vulns
    
    def _apply_triage_to_vulnerabilities(self, current_vulns: List[Dict], triage_results: List[Dict]) -> List[Dict]:
        """
        Apply triage analysis results to vulnerabilities
        
        Args:
            current_vulns: Current vulnerabilities list
            triage_results: Triage analysis results
            
        Returns:
            Vulnerabilities with triage information applied
        """
        triaged_vulns = current_vulns.copy()
        
        try:
            for vuln in triaged_vulns:
                vuln_id = vuln.get('id')
                # Find matching triage result
                for triage in triage_results:
                    if triage.get('vulnerability_id') == vuln_id:
                        vuln.update({
                            'final_status': triage.get('final_status'),
                            'confidence_level': triage.get('confidence_level'),
                            'priority': triage.get('priority'),
                            'risk_rating': triage.get('risk_rating'),
                            'exploitability_assessment': triage.get('exploitability_assessment'),
                            'remediation_priority': triage.get('remediation_priority'),
                            'triage_timestamp': datetime.utcnow()
                        })
                        break
                        
        except Exception as e:
            logger.error(f"Error applying triage to vulnerabilities: {e}")
            
        return triaged_vulns
    
    def get_scan_progress(self, document_id: str) -> Optional[Dict[str, Any]]:
        """
        Get current scan progress for a document
        
        Args:
            document_id: Document ID to check
            
        Returns:
            Progress information or None if not found
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return None
            
        try:
            from bson import ObjectId
            
            doc = self.collection.find_one(
                {'_id': ObjectId(document_id)},
                {
                    'status': 1,
                    'progress_tracking': 1,
                    'timestamp': 1,
                    'last_updated': 1,
                    'vulnerabilities': 1
                }
            )
            
            if not doc:
                return None
                
            progress_info = {
                'document_id': document_id,
                'status': doc.get('status'),
                'current_stage': doc.get('progress_tracking', {}).get('current_stage'),
                'completion_percentage': doc.get('progress_tracking', {}).get('completion_percentage', 0),
                'stages_completed': doc.get('progress_tracking', {}).get('stages_completed', []),
                'vulnerabilities_found': len(doc.get('vulnerabilities', [])),
                'started_at': doc.get('timestamp'),
                'last_updated': doc.get('last_updated')
            }
            
            return progress_info
            
        except Exception as e:
            logger.error(f"Failed to get scan progress: {e}")
            return None
    
    def get_vulnerabilities_by_document(self, document_id: str) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a specific document
        
        Args:
            document_id: Document ID
            
        Returns:
            List of vulnerabilities
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return []
            
        try:
            from bson import ObjectId
            
            doc = self.collection.find_one(
                {'_id': ObjectId(document_id)},
                {'vulnerabilities': 1}
            )
            
            if doc:
                return doc.get('vulnerabilities', [])
            return []
            
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []
    
    def complete_assessment(self, document_id: str, final_result: Dict[str, Any]) -> bool:
        """
        Mark assessment as completed with final results
        
        Args:
            document_id: Document ID to complete
            final_result: Final assessment results
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return False
            
        try:
            from bson import ObjectId
            
            # Get current document
            doc = self.collection.find_one({'_id': ObjectId(document_id)})
            if not doc:
                logger.warning(f"No document found with ID {document_id}")
                return False
            
            # Serialize the final result
            serialized_result = serialize_for_mongodb(final_result)
            
            # Ensure all stages are marked as completed
            stages_completed = ['pdf_analysis', 'static_analysis', 'dynamic_analysis', 'triage_analysis']
            
            # Update document as completed with new schema
            update_data = {
                'status': 'completed',
                'progress_tracking.current_stage': 'completed',
                'progress_tracking.completion_percentage': 100,
                'progress_tracking.stages_completed': stages_completed,
                'progress_tracking.estimated_completion': datetime.utcnow(),
                'final_result': serialized_result,
                'completion_timestamp': datetime.utcnow(),
                'last_updated': datetime.utcnow()
            }
            
            # Update document
            result = self.collection.update_one(
                {'_id': ObjectId(document_id)},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                logger.info(f"Assessment completed for document {document_id}")
                return True
            else:
                logger.warning(f"No document found with ID {document_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to complete assessment: {e}")
            return False
    
    # Legacy method - kept for backward compatibility
    def save_assessment_result(self, result: Dict[str, Any], 
                             pdf_path: str = None,
                             source_path: str = None,
                             target_url: str = None,
                             model_used: str = None,
                             execution_mode: str = None) -> Optional[str]:
        """
        Legacy method for saving assessment results (v1.0 schema)
        Deprecated: Use create_assessment_document + update_assessment_stage + complete_assessment instead
        """
        logger.warning("save_assessment_result is deprecated. Use the new v3.0 schema methods instead.")
        
        if self.collection is None:
            logger.error("Database not connected. Call connect() first.")
            return None
            
        try:
            document = {
                'timestamp': datetime.utcnow(),
                'execution_metadata': {
                    'pdf_path': pdf_path,
                    'source_path': source_path,
                    'target_url': target_url,
                    'model_used': model_used,
                    'execution_mode': execution_mode
                },
                'assessment_result': serialize_for_mongodb(result),
                'version': '1.0'
            }
            
            result = self.collection.insert_one(document)
            document_id = str(result.inserted_id)
            logger.info(f"Assessment result saved with ID: {document_id}")
            return document_id
            
        except Exception as e:
            logger.error(f"Failed to save assessment result: {e}")
            return None
    
    # Legacy method - kept for backward compatibility
    def save_triage_result(self, triage_result: Dict[str, Any], 
                          pdf_path: str = None,
                          source_path: str = None,
                          target_url: str = None,
                          model_used: str = None,
                          execution_mode: str = None) -> Optional[str]:
        """
        Legacy method for saving triage results (v1.0 schema)
        Deprecated: Use create_assessment_document + update_assessment_stage + complete_assessment instead
        """
        logger.warning("save_triage_result is deprecated. Use the new v3.0 schema methods instead.")
        
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