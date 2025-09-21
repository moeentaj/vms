# app/utils/api_responses.py
"""
Standardized API Response Utilities
Provides consistent response formatting across all endpoints
"""

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from typing import Any, Dict, Optional, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class APIResponse:
    """Standardized API response handler"""
    
    @staticmethod
    def success(
        data: Any = None, 
        message: str = "Success", 
        status_code: int = 200,
        meta: Optional[Dict] = None
    ) -> JSONResponse:
        """Standard success response"""
        response = {
            "success": True,
            "message": message,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if meta:
            response["meta"] = meta
            
        return JSONResponse(content=response, status_code=status_code)
    
    @staticmethod
    def error(
        message: str, 
        status_code: int = 400, 
        details: Optional[Dict] = None,
        error_code: Optional[str] = None
    ) -> HTTPException:
        """Standard error response"""
        error_response = {
            "success": False,
            "message": message,
            "error_code": error_code or f"HTTP_{status_code}",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if details:
            error_response["details"] = details
        
        logger.error(f"API Error {status_code}: {message}", extra={
            "error_code": error_code,
            "details": details
        })
        
        raise HTTPException(status_code=status_code, detail=error_response)
    
    @staticmethod
    def validation_error(errors: Dict[str, Any]) -> HTTPException:
        """Validation error response"""
        return APIResponse.error(
            message="Validation failed",
            status_code=422,
            details={"validation_errors": errors},
            error_code="VALIDATION_ERROR"
        )
    
    @staticmethod
    def not_found(resource: str, identifier: Any = None) -> HTTPException:
        """Resource not found error"""
        message = f"{resource} not found"
        if identifier:
            message += f" with identifier: {identifier}"
            
        return APIResponse.error(
            message=message,
            status_code=404,
            error_code="RESOURCE_NOT_FOUND"
        )
    
    @staticmethod
    def unauthorized(message: str = "Authentication required") -> HTTPException:
        """Unauthorized access error"""
        return APIResponse.error(
            message=message,
            status_code=401,
            error_code="UNAUTHORIZED"
        )
    
    @staticmethod
    def forbidden(message: str = "Access denied") -> HTTPException:
        """Forbidden access error"""
        return APIResponse.error(
            message=message,
            status_code=403,
            error_code="FORBIDDEN"
        )
    
    @staticmethod
    def paginated_response(
        data: List[Any],
        page: int,
        limit: int,
        total: int,
        message: str = "Success"
    ) -> JSONResponse:
        """Paginated response with metadata"""
        total_pages = (total + limit - 1) // limit  # Ceiling division
        
        meta = {
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            }
        }
        
        return APIResponse.success(
            data=data,
            message=message,
            meta=meta
        )

class ValidationHelper:
    """Helper functions for common validations"""
    
    @staticmethod
    def validate_pagination(page: int, limit: int) -> None:
        """Validate pagination parameters"""
        errors = {}
        
        if page < 1:
            errors["page"] = "Page must be >= 1"
            
        if limit < 1:
            errors["limit"] = "Limit must be >= 1"
        elif limit > 100:
            errors["limit"] = "Limit cannot exceed 100"
            
        if errors:
            raise APIResponse.validation_error(errors)
    
    @staticmethod
    def validate_required_fields(data: Dict, required_fields: List[str]) -> None:
        """Validate required fields are present and not empty"""
        errors = {}
        
        for field in required_fields:
            if field not in data:
                errors[field] = f"{field} is required"
            elif isinstance(data[field], str) and not data[field].strip():
                errors[field] = f"{field} cannot be empty"
            elif data[field] is None:
                errors[field] = f"{field} cannot be null"
                
        if errors:
            raise APIResponse.validation_error(errors)

# Decorators for common API patterns
def handle_api_errors(func):
    """Decorator to handle common API errors"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except HTTPException:
            # Re-raise HTTPExceptions (our custom errors)
            raise
        except ValueError as e:
            raise APIResponse.error(str(e), 400, error_code="INVALID_VALUE")
        except KeyError as e:
            raise APIResponse.error(f"Missing required field: {e}", 400, error_code="MISSING_FIELD")
        except Exception as e:
            logger.exception(f"Unexpected error in {func.__name__}")
            raise APIResponse.error(
                "Internal server error", 
                500, 
                error_code="INTERNAL_ERROR"
            )
    return wrapper

# Response status codes as constants
class StatusCodes:
    OK = 200
    CREATED = 201
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    VALIDATION_ERROR = 422
    INTERNAL_ERROR = 500