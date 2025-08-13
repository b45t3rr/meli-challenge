from crewai.tools import BaseTool
from typing import Type, Any, Dict, List
from pydantic import BaseModel, Field
import json
import logging
from ..utils.database import DatabaseManager

logger = logging.getLogger(__name__)

class DatabaseUpdateInput(BaseModel):
    """Input schema for database update tool"""
    document_id: str = Field(..., description="ID of the assessment document to update")
    stage: str = Field(..., description="Stage name (reader, static, dynamic, triage)")
    data: str = Field(..., description="JSON string containing the data to update")

class DatabaseCreateInput(BaseModel):
    """Input schema for database create tool"""
    pdf_path: str = Field(default=None, description="Path to the PDF file")
    source_path: str = Field(default=None, description="Path to the source code")
    target_url: str = Field(default=None, description="Target URL")
    model_used: str = Field(default=None, description="Model used for analysis")
    execution_mode: str = Field(default=None, description="Execution mode")

class DatabaseQueryInput(BaseModel):
    """Input schema for database query tool"""
    document_id: str = Field(..., description="ID of the assessment document to query")

class DatabaseUpdateTool(BaseTool):
    """Tool for updating assessment documents in the database"""
    
    name: str = "Database Update"
    description: str = (
        "Updates an assessment document in the database with new stage data. "
        "Use this to save results from each analysis stage (reader, static, dynamic, triage). "
        "The data should be a JSON string containing the analysis results."
    )
    args_schema: Type[BaseModel] = DatabaseUpdateInput
    
    def _run(self, document_id: str, stage: str, data: str) -> str:
        """Update assessment document with stage data"""
        try:
            # Parse the JSON data
            try:
                stage_data = json.loads(data)
            except json.JSONDecodeError as e:
                return f"Error parsing JSON data: {str(e)}"
            
            # Map stage names to database expected format
            stage_mapping = {
                'reader': 'pdf_analysis',
                'static': 'static_analysis', 
                'dynamic': 'dynamic_analysis',
                'triage': 'triage_analysis'
            }
            
            db_stage = stage_mapping.get(stage, stage)
            
            # Initialize database connection
            db_manager = DatabaseManager()
            if not db_manager.connect():
                return "Error: Could not connect to database"
            
            # Update the assessment stage
            success = db_manager.update_assessment_stage(document_id, db_stage, stage_data)
            
            if success:
                logger.info(f"Successfully updated {stage} stage for document {document_id}")
                return f"Successfully updated {stage} stage data for document {document_id}"
            else:
                return f"Failed to update {stage} stage for document {document_id}"
                
        except Exception as e:
            logger.error(f"Error updating database: {e}")
            return f"Error updating database: {str(e)}"
        finally:
            if 'db_manager' in locals():
                db_manager.close_connection()

class DatabaseCreateTool(BaseTool):
    """Tool for creating new assessment documents in the database"""
    
    name: str = "Database Create"
    description: str = (
        "Creates a new assessment document in the database. "
        "Use this at the beginning of an analysis to create a document that can be updated later. "
        "Returns the document ID that should be used for subsequent updates."
    )
    args_schema: Type[BaseModel] = DatabaseCreateInput
    
    def _run(self, pdf_path: str = None, source_path: str = None, target_url: str = None, 
             model_used: str = None, execution_mode: str = None) -> str:
        """Create new assessment document"""
        try:
            # Initialize database connection
            db_manager = DatabaseManager()
            if not db_manager.connect():
                return "Error: Could not connect to database"
            
            # Create the assessment document
            document_id = db_manager.create_assessment_document(
                pdf_path=pdf_path,
                source_path=source_path,
                target_url=target_url,
                model_used=model_used,
                execution_mode=execution_mode
            )
            
            if document_id:
                logger.info(f"Successfully created assessment document {document_id}")
                return f"Successfully created assessment document with ID: {document_id}"
            else:
                return "Failed to create assessment document"
                
        except Exception as e:
            logger.error(f"Error creating assessment document: {e}")
            return f"Error creating assessment document: {str(e)}"
        finally:
            if 'db_manager' in locals():
                db_manager.close_connection()

class DatabaseQueryTool(BaseTool):
    """Tool for querying assessment documents from the database"""
    
    name: str = "Database Query"
    description: str = (
        "Queries an assessment document from the database by ID. "
        "Use this to retrieve current state of an assessment or check what data has been stored."
    )
    args_schema: Type[BaseModel] = DatabaseQueryInput
    
    def _run(self, document_id: str) -> str:
        """Query assessment document by ID"""
        try:
            # Initialize database connection
            db_manager = DatabaseManager()
            if not db_manager.connect():
                return "Error: Could not connect to database"
            
            # Get the assessment document
            document = db_manager.get_assessment_by_id(document_id)
            
            if document:
                # Convert to JSON string for return
                return json.dumps(document, indent=2, default=str)
            else:
                return f"No assessment document found with ID: {document_id}"
                
        except Exception as e:
            logger.error(f"Error querying database: {e}")
            return f"Error querying database: {str(e)}"
        finally:
            if 'db_manager' in locals():
                db_manager.close_connection()