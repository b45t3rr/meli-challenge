from crewai.tools import BaseTool
from typing import Type, Any, List
from pydantic import BaseModel, Field
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class FileReaderInput(BaseModel):
    """Input schema for file reader tool"""
    file_path: str = Field(..., description="Path to the file to read")
    max_lines: int = Field(default=1000, description="Maximum number of lines to read")

class DirectoryListInput(BaseModel):
    """Input schema for directory listing tool"""
    directory_path: str = Field(..., description="Path to the directory to list")
    recursive: bool = Field(default=False, description="Whether to list files recursively")
    file_extensions: List[str] = Field(default=[], description="Filter by file extensions (e.g., ['.py', '.js'])")

class FileSearchInput(BaseModel):
    """Input schema for file search tool"""
    directory_path: str = Field(..., description="Path to search in")
    pattern: str = Field(..., description="Search pattern or filename")
    case_sensitive: bool = Field(default=False, description="Whether search is case sensitive")

class FileReaderTool(BaseTool):
    """Tool for reading file contents"""
    
    name: str = "File Reader"
    description: str = (
        "Reads the contents of text files. "
        "Useful for examining source code, configuration files, and other text documents. "
        "Can limit the number of lines read to avoid overwhelming output."
    )
    args_schema: Type[BaseModel] = FileReaderInput
    
    def _run(self, file_path: str, max_lines: int = 1000) -> str:
        """Read file contents"""
        try:
            return self.read_file(file_path, max_lines)
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return f"Error reading file: {str(e)}"
    
    def read_file(self, file_path: str, max_lines: int = 1000) -> str:
        """Read file contents with line limit"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not os.path.isfile(file_path):
            raise ValueError(f"Path is not a file: {file_path}")
        
        # Check if file is likely to be text
        if not self._is_text_file(file_path):
            return f"Warning: File '{file_path}' appears to be binary and cannot be read as text."
        
        logger.info(f"Reading file: {file_path} (max {max_lines} lines)")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = []
                for i, line in enumerate(file, 1):
                    if i > max_lines:
                        lines.append(f"\n... (truncated after {max_lines} lines) ...")
                        break
                    lines.append(line.rstrip('\n\r'))
                
                content = '\n'.join(lines)
                logger.info(f"Read {len(lines)} lines from {file_path}")
                return content
                
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1', errors='ignore') as file:
                    content = file.read()
                    if len(content.split('\n')) > max_lines:
                        lines = content.split('\n')[:max_lines]
                        content = '\n'.join(lines) + f"\n... (truncated after {max_lines} lines) ..."
                    return content
            except Exception as e:
                raise ValueError(f"Cannot decode file {file_path}: {str(e)}")
        except Exception as e:
            raise ValueError(f"Error reading file {file_path}: {str(e)}")
    
    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is likely to be a text file"""
        # Check by extension first
        text_extensions = {
            '.txt', '.py', '.js', '.html', '.htm', '.css', '.json', '.xml', '.yaml', '.yml',
            '.md', '.rst', '.csv', '.sql', '.sh', '.bat', '.ps1', '.php', '.rb', '.go',
            '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.vb', '.pl', '.r', '.scala',
            '.swift', '.kt', '.ts', '.jsx', '.tsx', '.vue', '.svelte', '.cfg', '.conf',
            '.ini', '.properties', '.log', '.dockerfile', '.gitignore', '.env'
        }
        
        file_ext = Path(file_path).suffix.lower()
        if file_ext in text_extensions:
            return True
        
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type and mime_type.startswith('text/'):
            return True
        
        # Check file size (avoid very large files)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                return False
        except:
            pass
        
        # Sample first few bytes to check for binary content
        try:
            with open(file_path, 'rb') as file:
                sample = file.read(1024)
                # Check for null bytes (common in binary files)
                if b'\x00' in sample:
                    return False
                # Check if most bytes are printable
                printable_ratio = sum(1 for byte in sample if 32 <= byte <= 126 or byte in [9, 10, 13]) / len(sample)
                return printable_ratio > 0.7
        except:
            return False

class DirectoryListTool(BaseTool):
    """Tool for listing directory contents"""
    
    name: str = "Directory Lister"
    description: str = (
        "Lists files and directories in a given path. "
        "Can filter by file extensions and list recursively. "
        "Useful for exploring project structure and finding relevant files."
    )
    args_schema: Type[BaseModel] = DirectoryListInput
    
    def _run(self, directory_path: str, recursive: bool = False, file_extensions: List[str] = None) -> str:
        """List directory contents"""
        try:
            return self.list_directory(directory_path, recursive, file_extensions or [])
        except Exception as e:
            logger.error(f"Error listing directory {directory_path}: {e}")
            return f"Error listing directory: {str(e)}"
    
    def list_directory(self, directory_path: str, recursive: bool = False, file_extensions: List[str] = None) -> str:
        """List directory contents with filtering"""
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not os.path.isdir(directory_path):
            raise ValueError(f"Path is not a directory: {directory_path}")
        
        logger.info(f"Listing directory: {directory_path} (recursive: {recursive})")
        
        file_extensions = file_extensions or []
        file_extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in file_extensions]
        
        results = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    # Skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    level = root.replace(directory_path, '').count(os.sep)
                    indent = '  ' * level
                    results.append(f"{indent}{os.path.basename(root)}/")
                    
                    subindent = '  ' * (level + 1)
                    for file in sorted(files):
                        if file.startswith('.'):
                            continue
                        
                        if file_extensions:
                            file_ext = Path(file).suffix.lower()
                            if file_ext not in file_extensions:
                                continue
                        
                        file_path = os.path.join(root, file)
                        file_size = self._get_file_size(file_path)
                        results.append(f"{subindent}{file} ({file_size})")
            else:
                items = sorted(os.listdir(directory_path))
                for item in items:
                    if item.startswith('.'):
                        continue
                    
                    item_path = os.path.join(directory_path, item)
                    
                    if os.path.isdir(item_path):
                        results.append(f"{item}/")
                    else:
                        if file_extensions:
                            file_ext = Path(item).suffix.lower()
                            if file_ext not in file_extensions:
                                continue
                        
                        file_size = self._get_file_size(item_path)
                        results.append(f"{item} ({file_size})")
            
            if not results:
                return f"Directory '{directory_path}' is empty or no files match the criteria."
            
            return '\n'.join(results)
            
        except PermissionError:
            raise ValueError(f"Permission denied accessing directory: {directory_path}")
        except Exception as e:
            raise ValueError(f"Error listing directory {directory_path}: {str(e)}")
    
    def _get_file_size(self, file_path: str) -> str:
        """Get human-readable file size"""
        try:
            size = os.path.getsize(file_path)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f}{unit}"
                size /= 1024.0
            return f"{size:.1f}TB"
        except:
            return "Unknown"

class SemgrepInput(BaseModel):
    """Input schema for Semgrep tool"""
    source_path: str = Field(..., description="Path to the source code directory or file to scan")
    config: str = Field(default="auto", description="Semgrep configuration to use (auto, p/security-audit, etc.)")
    max_results: int = Field(default=50, description="Maximum number of results to return")

class SemgrepTool(BaseTool):
    """Tool for running Semgrep static analysis"""
    
    name: str = "Semgrep"
    description: str = (
        "Runs Semgrep static analysis on source code to find security vulnerabilities, "
        "bugs, and code quality issues. Returns findings in JSON format with details "
        "about potential security issues."
    )
    args_schema: Type[BaseModel] = SemgrepInput
    
    def _run(self, source_path: str, config: str = "auto", max_results: int = 50) -> str:
        """Run Semgrep scan"""
        try:
            return self.run_semgrep_scan(source_path, config, max_results)
        except Exception as e:
            logger.error(f"Error running Semgrep on {source_path}: {e}")
            return f"Error running Semgrep: {str(e)}"
    
    def run_semgrep_scan(self, source_path: str, config: str = "auto", max_results: int = 50) -> str:
        """Run Semgrep security scan on the source code"""
        import subprocess
        import json
        
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source path not found: {source_path}")
        
        logger.info(f"Running Semgrep scan on: {source_path}")
        
        try:
            # Run Semgrep with security rules
            cmd = [
                "semgrep",
                f"--config={config}",
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
                    results = semgrep_output.get('results', [])
                    
                    # Limit results to avoid overwhelming output
                    if len(results) > max_results:
                        results = results[:max_results]
                        logger.info(f"Limiting Semgrep results to {max_results} items")
                    
                    # Format results for better readability
                    formatted_results = []
                    for r in results:
                        formatted_results.append({
                            'rule_id': r.get('check_id', 'Unknown'),
                            'message': r.get('message', 'No message'),
                            'severity': r.get('extra', {}).get('severity', 'Unknown'),
                            'file_path': r.get('path', 'Unknown'),
                            'line_start': r.get('start', {}).get('line', 'Unknown'),
                            'line_end': r.get('end', {}).get('line', 'Unknown'),
                            'code_snippet': r.get('extra', {}).get('lines', 'No code available')
                        })
                    
                    summary = {
                        'total_findings': len(results),
                        'scan_path': source_path,
                        'config_used': config,
                        'findings': formatted_results
                    }
                    
                    logger.info(f"Semgrep found {len(results)} potential issues")
                    return json.dumps(summary, indent=2)
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse Semgrep JSON output")
                    return json.dumps({"error": "Failed to parse Semgrep output", "raw_output": result.stdout})
            else:
                logger.error(f"Semgrep failed with return code {result.returncode}")
                logger.error(f"Stderr: {result.stderr}")
                return json.dumps({"error": f"Semgrep execution failed: {result.stderr}"})
                
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return json.dumps({"error": "Semgrep scan timed out after 5 minutes"})
        except FileNotFoundError:
            logger.error("Semgrep not found. Please install semgrep.")
            return json.dumps({"error": "Semgrep not installed. Please run: pip install semgrep"})
        except Exception as e:
            logger.error(f"Unexpected error running Semgrep: {e}")
            return json.dumps({"error": f"Unexpected error: {str(e)}"})

class FileSearchTool(BaseTool):
    """Tool for searching files by name or pattern"""
    
    name: str = "File Search"
    description: str = (
        "Searches for files by name or pattern in a directory tree. "
        "Useful for finding specific files or files matching certain patterns."
    )
    args_schema: Type[BaseModel] = FileSearchInput
    
    def _run(self, directory_path: str, pattern: str, case_sensitive: bool = False) -> str:
        """Search for files"""
        try:
            return self.search_files(directory_path, pattern, case_sensitive)
        except Exception as e:
            logger.error(f"Error searching files in {directory_path}: {e}")
            return f"Error searching files: {str(e)}"
    
    def search_files(self, directory_path: str, pattern: str, case_sensitive: bool = False) -> str:
        """Search for files matching pattern"""
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not os.path.isdir(directory_path):
            raise ValueError(f"Path is not a directory: {directory_path}")
        
        logger.info(f"Searching for pattern '{pattern}' in {directory_path}")
        
        import fnmatch
        
        if not case_sensitive:
            pattern = pattern.lower()
        
        matches = []
        
        try:
            for root, dirs, files in os.walk(directory_path):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if file.startswith('.'):
                        continue
                    
                    search_name = file if case_sensitive else file.lower()
                    
                    if fnmatch.fnmatch(search_name, pattern) or pattern in search_name:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, directory_path)
                        file_size = self._get_file_size(file_path)
                        matches.append(f"{rel_path} ({file_size})")
            
            if not matches:
                return f"No files found matching pattern '{pattern}' in {directory_path}"
            
            return f"Found {len(matches)} files:\n" + '\n'.join(sorted(matches))
            
        except Exception as e:
            raise ValueError(f"Error searching files: {str(e)}")
    
    def _get_file_size(self, file_path: str) -> str:
        """Get human-readable file size"""
        try:
            size = os.path.getsize(file_path)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f}{unit}"
                size /= 1024.0
            return f"{size:.1f}TB"
        except:
            return "Unknown"