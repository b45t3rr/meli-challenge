from crewai.tools import BaseTool
from typing import Type, Any
from pydantic import BaseModel, Field
import PyPDF2
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class PDFReaderInput(BaseModel):
    """Input schema for PDF reader tool"""
    pdf_path: str = Field(..., description="Path to the PDF file to read")

class PDFReaderTool(BaseTool):
    """Tool for reading and extracting text from PDF files"""
    
    name: str = "PDF Reader"
    description: str = (
        "Extracts text content from PDF files. "
        "Useful for reading vulnerability reports, documentation, and other PDF documents. "
        "Returns the full text content of the PDF file."
    )
    args_schema: Type[BaseModel] = PDFReaderInput
    
    def _run(self, pdf_path: str) -> str:
        """Extract text from PDF file"""
        try:
            return self.extract_text(pdf_path)
        except Exception as e:
            logger.error(f"Error reading PDF {pdf_path}: {e}")
            return f"Error reading PDF: {str(e)}"
    
    def extract_text(self, pdf_path: str) -> str:
        """Extract text from PDF file using PyPDF2"""
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        
        if not pdf_path.lower().endswith('.pdf'):
            raise ValueError(f"File is not a PDF: {pdf_path}")
        
        logger.info(f"Extracting text from PDF: {pdf_path}")
        
        try:
            text_content = []
            
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                logger.info(f"PDF has {len(pdf_reader.pages)} pages")
                
                for page_num, page in enumerate(pdf_reader.pages, 1):
                    try:
                        page_text = page.extract_text()
                        if page_text.strip():  # Only add non-empty pages
                            text_content.append(f"\n--- Page {page_num} ---\n")
                            text_content.append(page_text)
                            logger.debug(f"Extracted {len(page_text)} characters from page {page_num}")
                    except Exception as e:
                        logger.warning(f"Error extracting text from page {page_num}: {e}")
                        text_content.append(f"\n--- Page {page_num} (Error) ---\n")
                        text_content.append(f"Error extracting page: {str(e)}")
            
            full_text = ''.join(text_content)
            
            if not full_text.strip():
                logger.warning("No text content extracted from PDF")
                return "Warning: No readable text content found in the PDF file. The PDF might be image-based or encrypted."
            
            logger.info(f"Successfully extracted {len(full_text)} characters from PDF")
            return full_text
            
        except PyPDF2.errors.PdfReadError as e:
            logger.error(f"PDF read error: {e}")
            raise ValueError(f"Cannot read PDF file (might be corrupted or encrypted): {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error reading PDF: {e}")
            raise
    
    def get_pdf_metadata(self, pdf_path: str) -> dict:
        """Extract metadata from PDF file"""
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                metadata = {
                    'num_pages': len(pdf_reader.pages),
                    'file_size': os.path.getsize(pdf_path),
                    'file_name': Path(pdf_path).name
                }
                
                # Try to get PDF metadata
                if pdf_reader.metadata:
                    metadata.update({
                        'title': pdf_reader.metadata.get('/Title', 'Unknown'),
                        'author': pdf_reader.metadata.get('/Author', 'Unknown'),
                        'subject': pdf_reader.metadata.get('/Subject', 'Unknown'),
                        'creator': pdf_reader.metadata.get('/Creator', 'Unknown'),
                        'producer': pdf_reader.metadata.get('/Producer', 'Unknown'),
                        'creation_date': str(pdf_reader.metadata.get('/CreationDate', 'Unknown')),
                        'modification_date': str(pdf_reader.metadata.get('/ModDate', 'Unknown'))
                    })
                
                return metadata
                
        except Exception as e:
            logger.error(f"Error extracting PDF metadata: {e}")
            return {'error': str(e)}
    
    def extract_text_by_page(self, pdf_path: str, start_page: int = 1, end_page: int = None) -> dict:
        """Extract text from specific pages"""
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                total_pages = len(pdf_reader.pages)
                
                if end_page is None:
                    end_page = total_pages
                
                # Validate page range
                start_page = max(1, start_page)
                end_page = min(total_pages, end_page)
                
                pages_text = {}
                
                for page_num in range(start_page - 1, end_page):
                    try:
                        page = pdf_reader.pages[page_num]
                        page_text = page.extract_text()
                        pages_text[page_num + 1] = page_text
                    except Exception as e:
                        pages_text[page_num + 1] = f"Error extracting page: {str(e)}"
                
                return {
                    'total_pages': total_pages,
                    'extracted_pages': f"{start_page}-{end_page}",
                    'pages_text': pages_text
                }
                
        except Exception as e:
            logger.error(f"Error extracting text by page: {e}")
            return {'error': str(e)}