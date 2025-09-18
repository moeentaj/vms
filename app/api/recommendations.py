from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload, aliased
from sqlalchemy import and_, or_, func
from app.core.database import get_db
from app.models.vulnerability_assignment import VulnerabilityAssignment, AssignmentStatus, AssignmentPriority
from app.models.user import User
from app.models.cve import CVE
from app.models.asset import Asset
from app.api.auth import get_current_user
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

class AssignmentCreate(BaseModel):
    cve_id: str
    asset_id: Optional[int] = None
    assignee_id: int
    title: str
    description: Optional[str] = None
    priority: AssignmentPriority = AssignmentPriority.MEDIUM
    due_date: Optional[datetime] = None

class AssignmentUpdate(BaseModel):
    status: Optional[AssignmentStatus] = None
    priority: Optional[AssignmentPriority] = None
    progress_notes: Optional[str] = None
    resolution_summary: Optional[str] = None
    due_date: Optional[datetime] = None

class AssignmentResponse(BaseModel):
    id: int
    cve_id: str
    asset_id: Optional[int]
    title: str
    description: Optional[str]
    status: AssignmentStatus
    priority: AssignmentPriority
    due_date: Optional[datetime]
    assigned_at: datetime
    completed_at: Optional[datetime]
    progress_notes: Optional[str]
    
    # Related data
    assignee_name: str
    assigned_by_name: str
    cve_description: str
    asset_name: Optional[str]
    
    class Config:
        from_attributes = True

@router.post("/", response_model=dict)
async def create_assignment(
    assignment: AssignmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new vulnerability assignment"""
    
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Validate CVE exists
    cve = db.query(CVE).filter(CVE.cve_id == assignment.cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    
    # Validate assignee exists
    assignee = db.query(User).filter(User.id == assignment.assignee_id).first()
    if not assignee or not assignee.is_active:
        raise HTTPException(status_code=404, detail="Assignee not found or inactive")
    
    # Validate asset if provided
    if assignment.asset_id:
        asset = db.query(Asset).filter(Asset.id == assignment.asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
    
    # Create assignment
    db_assignment = VulnerabilityAssignment(
        cve_id=assignment.cve_id,
        asset_id=assignment.asset_id,
        assignee_id=assignment.assignee_id,
        assigned_by_id=current_user.id,
        title=assignment.title,
        description=assignment.description,
        priority=assignment.priority,
        due_date=assignment.due_date
    )
    
    db.add(db_assignment)
    db.commit()
    db.refresh(db_assignment)
    
    return {
        "message": "Assignment created successfully",
        "assignment_id": db_assignment.id,
        "assignee": assignee.username
    }

@router.get("/", response_model=List[AssignmentResponse])
async def get_assignments(
    status: Optional[AssignmentStatus] = None,
    assignee_id: Optional[int] = None,
    my_assignments: bool = Query(False),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get vulnerability assignments with filtering"""
    
    try:
        # Use joins to fetch all related data in one query
        assigned_by_user = aliased(User, name='assigned_by')
        query = db.query(VulnerabilityAssignment)\
            .join(User, VulnerabilityAssignment.assignee_id == User.id, isouter=False)\
            .join(assigned_by_user, VulnerabilityAssignment.assigned_by_id == assigned_by_user.id, isouter=False)\
            .join(CVE, VulnerabilityAssignment.cve_id == CVE.cve_id, isouter=False)\
            .outerjoin(Asset, VulnerabilityAssignment.asset_id == Asset.id)
        
        # Alternative approach using eager loading
        query = db.query(VulnerabilityAssignment)
        
        # Filter by assignee
        if my_assignments:
            query = query.filter(VulnerabilityAssignment.assignee_id == current_user.id)
        elif assignee_id:
            query = query.filter(VulnerabilityAssignment.assignee_id == assignee_id)
        
        # Filter by status
        if status and status.strip():  # Only filter if status is not empty
            try:
                status_enum = AssignmentStatus(status)
                query = query.filter(VulnerabilityAssignment.status == status_enum)
            except ValueError:
                # Invalid status value, don't filter
                pass
        
        # For non-admin users, only show their assignments
        if current_user.role not in ["admin", "manager"]:
            query = query.filter(
                or_(
                    VulnerabilityAssignment.assignee_id == current_user.id,
                    VulnerabilityAssignment.assigned_by_id == current_user.id
                )
            )
        
        assignments = query.offset(skip).limit(limit).all()
        
        # Build response with related data - fixed to handle None values properly
        result = []
        for assignment in assignments:
            try:
                # Fetch related data with proper error handling
                assignee = db.query(User).filter(User.id == assignment.assignee_id).first()
                assigned_by = db.query(User).filter(User.id == assignment.assigned_by_id).first()
                cve = db.query(CVE).filter(CVE.cve_id == assignment.cve_id).first()
                asset = None
                if assignment.asset_id:
                    asset = db.query(Asset).filter(Asset.id == assignment.asset_id).first()
                
                # Handle missing related data gracefully
                if not assignee or not assigned_by or not cve:
                    logger.error(f"Missing related data for assignment {assignment.id}")
                    continue
                
                # Safely build names
                assignee_name = "Unknown User"
                if assignee:
                    if assignee.first_name and assignee.last_name:
                        assignee_name = f"{assignee.first_name} {assignee.last_name}"
                    elif assignee.username:
                        assignee_name = assignee.username
                
                assigned_by_name = "Unknown User"
                if assigned_by:
                    if assigned_by.first_name and assigned_by.last_name:
                        assigned_by_name = f"{assigned_by.first_name} {assigned_by.last_name}"
                    elif assigned_by.username:
                        assigned_by_name = assigned_by.username
                
                # Safely handle CVE description
                cve_description = ""
                if cve and cve.description:
                    cve_description = cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
                
                # Safely handle asset name
                asset_name = asset.name if asset else None
                
                result.append(AssignmentResponse(
                    id=assignment.id,
                    cve_id=assignment.cve_id,
                    asset_id=assignment.asset_id,
                    title=assignment.title or "",
                    description=assignment.description or "",
                    status=assignment.status,
                    priority=assignment.priority,
                    due_date=assignment.due_date,
                    assigned_at=assignment.assigned_at,
                    completed_at=assignment.completed_at,
                    progress_notes=assignment.progress_notes or "",
                    assignee_name=assignee_name,
                    assigned_by_name=assigned_by_name,
                    cve_description=cve_description,
                    asset_name=asset_name
                ))
            except Exception as e:
                logger.error(f"Error processing assignment {assignment.id}: {str(e)}")
                continue
        
        return result
        
    except Exception as e:
        logger.error(f"Error in get_assignments: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.put("/{assignment_id}", response_model=dict)
async def update_assignment(
    assignment_id: int,
    assignment_update: AssignmentUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update assignment status and progress"""
    
    try:
        assignment = db.query(VulnerabilityAssignment).filter(VulnerabilityAssignment.id == assignment_id).first()
        if not assignment:
            raise HTTPException(status_code=404, detail="Assignment not found")
        
        # Check permissions
        if (current_user.role not in ["admin", "manager"] and 
            assignment.assignee_id != current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Update fields
        update_data = assignment_update.dict(exclude_unset=True)
        
        for field, value in update_data.items():
            setattr(assignment, field, value)
        
        # Set timestamps based on status changes
        if assignment_update.status == AssignmentStatus.IN_PROGRESS and not assignment.started_at:
            assignment.started_at = datetime.utcnow()
        elif assignment_update.status in [AssignmentStatus.COMPLETED, AssignmentStatus.CLOSED]:
            assignment.completed_at = datetime.utcnow()
        
        db.commit()
        
        return {"message": "Assignment updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating assignment {assignment_id}: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/dashboard")
async def get_dashboard_data(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get dashboard data for vulnerability management"""
    
    try:
        logger.info("=== Dashboard endpoint accessed ===")
        logger.info(f"Current user: {current_user.username if current_user else 'None'}")
        
        # Count statistics
        total_cves = db.query(CVE).count()
        total_assets = db.query(Asset).count()
        high_risk_cves = db.query(CVE).filter(CVE.cvss_score >= 7.0).count()
        critical_assets = db.query(Asset).filter(Asset.criticality == "critical").count()
        
        # Recent CVEs (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_cves = db.query(CVE).filter(
            CVE.published_date >= thirty_days_ago
        ).count()
        
        # Top 10 highest risk CVEs
        top_cves = db.query(CVE).filter(
            CVE.cvss_score.isnot(None)
        ).order_by(CVE.cvss_score.desc()).limit(10).all()
        
        # Asset breakdown by environment - FIXED: Use func from sqlalchemy, not db.func
        asset_breakdown = db.query(
            Asset.environment,
            func.count(Asset.id).label('count')  # FIXED: func instead of db.func
        ).group_by(Asset.environment).all()
        
        # Asset breakdown by criticality - FIXED: Use func from sqlalchemy, not db.func
        criticality_breakdown = db.query(
            Asset.criticality,
            func.count(Asset.id).label('count')  # FIXED: func instead of db.func
        ).group_by(Asset.criticality).all()
        
        logger.info(f"Dashboard data prepared successfully")
        
        return {
            "statistics": {
                "total_cves": total_cves,
                "total_assets": total_assets,
                "high_risk_cves": high_risk_cves,
                "critical_assets": critical_assets,
                "recent_cves": recent_cves
            },
            "top_cves": [
                {
                    "cve_id": cve.cve_id,
                    "cvss_score": cve.cvss_score,
                    "severity": cve.severity,
                    "description": cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
                }
                for cve in top_cves
            ],
            "asset_breakdown": {
                "by_environment": {item.environment: item.count for item in asset_breakdown},
                "by_criticality": {item.criticality: item.count for item in criticality_breakdown}
            }
        }
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Dashboard error: {str(e)}")


@router.get("/dashboard/stats")
async def get_assignment_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assignment statistics for dashboard"""
    
    try:
        base_query = db.query(VulnerabilityAssignment)
        
        # For non-admin users, only show their assignments
        if current_user.role not in ["admin", "manager"]:
            base_query = base_query.filter(VulnerabilityAssignment.assignee_id == current_user.id)
        
        # Count by status
        status_counts = {}
        for status in AssignmentStatus:
            count = base_query.filter(VulnerabilityAssignment.status == status).count()
            status_counts[status.value] = count
        
        # Count overdue assignments
        overdue = base_query.filter(
            and_(
                VulnerabilityAssignment.due_date < datetime.utcnow(),
                VulnerabilityAssignment.status.in_([AssignmentStatus.ASSIGNED, AssignmentStatus.IN_PROGRESS])
            )
        ).count()
        
        # Count by priority
        priority_counts = {}
        for priority in AssignmentPriority:
            count = base_query.filter(
                and_(
                    VulnerabilityAssignment.priority == priority,
                    VulnerabilityAssignment.status.in_([AssignmentStatus.ASSIGNED, AssignmentStatus.IN_PROGRESS])
                )
            ).count()
            priority_counts[priority.value] = count
        
        return {
            "status_counts": status_counts,
            "overdue_count": overdue,
            "priority_counts": priority_counts,
            "total_active": status_counts.get("assigned", 0) + status_counts.get("in_progress", 0)
        }
        
    except Exception as e:
        logger.error(f"Error getting assignment stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")