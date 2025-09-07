import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import Counter
import logging

logger = logging.getLogger(__name__)


class CloudTrailDataLoader:
    """
    File-based CloudTrail data loader for JSON files.
    """
    
    def load_from_json_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Load CloudTrail logs from a single JSON file.
        
        Args:
            file_path: Path to the JSON file
            
        Returns:
            List of CloudTrail log records
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both direct list of records and CloudTrail JSON format
            if isinstance(data, dict) and 'Records' in data:
                records = data['Records']
            elif isinstance(data, list):
                records = data
            else:
                logger.warning(f"Unexpected JSON structure in {file_path}")
                return []
            
            logger.info(f"Loaded {len(records)} records from {file_path}")
            return records
            
        except Exception as e:
            logger.error(f"Error loading file {file_path}: {e}")
            return []
    
    def load_from_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """
        Load CloudTrail logs from all JSON files in a directory.
        
        Args:
            directory_path: Path to the directory containing JSON files
            
        Returns:
            List of CloudTrail log records
        """
        all_records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            logger.error(f"Directory does not exist: {directory_path}")
            return []
        
        json_files = list(directory.glob("*.json"))
        
        if not json_files:
            logger.warning(f"No JSON files found in {directory_path}")
            return []
        
        for json_file in json_files:
            records = self.load_from_json_file(str(json_file))
            all_records.extend(records)
        
        logger.info(f"Loaded {len(all_records)} total records from {len(json_files)} files")
        return all_records
    
    def validate_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate and filter CloudTrail logs.
        
        Args:
            logs: Raw CloudTrail log records
            
        Returns:
            List of valid CloudTrail log records
        """
        valid_logs = []
        
        required_fields = ['eventTime', 'eventName', 'eventSource']
        
        for log in logs:
            # Check for required fields
            if all(field in log for field in required_fields):
                # Basic validation
                if log.get('eventTime') and log.get('eventName') and log.get('eventSource'):
                    valid_logs.append(log)
                else:
                    logger.debug(f"Log missing required data: {log.get('eventName', 'Unknown')}")
            else:
                logger.debug(f"Log missing required fields: {list(log.keys())}")
        
        logger.info(f"Validated {len(valid_logs)} out of {len(logs)} logs")
        return valid_logs
    
    def filter_logs_by_time(self, logs: List[Dict[str, Any]], 
                           start_time: Optional[str] = None, 
                           end_time: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Filter logs by time range.
        
        Args:
            logs: CloudTrail log records
            start_time: Start time in ISO format (e.g., '2024-01-01T00:00:00Z')
            end_time: End time in ISO format
            
        Returns:
            Filtered list of CloudTrail log records
        """
        if not start_time and not end_time:
            return logs
        
        filtered_logs = []
        
        try:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00')) if start_time else None
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00')) if end_time else None
        except ValueError as e:
            logger.error(f"Invalid time format: {e}")
            return logs
        
        for log in logs:
            try:
                event_time_str = log.get('eventTime', '')
                if not event_time_str:
                    continue
                
                event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                
                # Apply time filters
                if start_dt and event_dt < start_dt:
                    continue
                if end_dt and event_dt > end_dt:
                    continue
                
                filtered_logs.append(log)
                
            except ValueError:
                logger.debug(f"Invalid eventTime format: {log.get('eventTime')}")
                continue
        
        logger.info(f"Filtered to {len(filtered_logs)} logs within time range")
        return filtered_logs
    
    def get_data_summary(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for the log data.
        
        Args:
            logs: CloudTrail log records
            
        Returns:
            Dictionary containing summary statistics
        """
        if not logs:
            return {
                'total_logs': 0,
                'time_range': {},
                'unique_user_agents': 0,
                'top_event_sources': {},
                'top_event_names': {}
            }
        
        # Basic counts
        event_sources = [log.get('eventSource', 'Unknown') for log in logs]
        event_names = [log.get('eventName', 'Unknown') for log in logs]
        user_agents = set(log.get('userAgent', 'Unknown') for log in logs)
        
        # Time range
        event_times = []
        for log in logs:
            event_time_str = log.get('eventTime')
            if event_time_str:
                try:
                    event_times.append(datetime.fromisoformat(event_time_str.replace('Z', '+00:00')))
                except ValueError:
                    continue
        
        time_range = {}
        if event_times:
            time_range = {
                'earliest': min(event_times).isoformat(),
                'latest': max(event_times).isoformat()
            }
        
        return {
            'total_logs': len(logs),
            'time_range': time_range,
            'unique_user_agents': len(user_agents),
            'top_event_sources': dict(Counter(event_sources).most_common(10)),
            'top_event_names': dict(Counter(event_names).most_common(10))
        }