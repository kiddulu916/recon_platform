"""
Scan job manager for orchestrating complete scan workflows
Manages scan lifecycle, progress tracking, and phase execution
"""

from typing import Dict, Optional, List
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
import uuid
import json
import asyncio

from app.models.scan import ScanJob
from app.models.domain import Domain, Subdomain

logger = structlog.get_logger()


class ScanJobManager:
    """
    Manages complete scan job workflows
    Orchestrates horizontal, passive, active, probing, and recursive phases
    """
    
    def __init__(self, config, scanner_engine):
        self.config = config
        self.scanner_engine = scanner_engine
        self.logger = logger.bind(component="job_manager")
        
        # Active jobs tracking
        self.active_jobs: Dict[str, asyncio.Task] = {}
    
    async def create_job(
        self,
        session: AsyncSession,
        domain_id: int,
        scan_type: str = "full",
        scan_profile: str = "normal",
        enable_recursion: bool = False,
        recursion_depth: int = 2
    ) -> ScanJob:
        """
        Create a new scan job
        
        Args:
            session: Database session
            domain_id: Target domain ID
            scan_type: Type of scan (full, subdomain, port, web)
            scan_profile: Scan profile (passive, normal, aggressive)
            enable_recursion: Enable recursive enumeration
            recursion_depth: Maximum recursion depth
        
        Returns:
            Created ScanJob instance
        """
        # Get domain
        domain = await session.get(Domain, domain_id)
        if not domain:
            raise ValueError(f"Domain {domain_id} not found")
        
        # Create job
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            domain_id=domain_id,
            scan_type=scan_type,
            scan_profile=scan_profile,
            status="pending",
            configuration=json.dumps({
                "enable_recursion": enable_recursion,
                "recursion_depth": recursion_depth
            })
        )
        
        session.add(job)
        await session.commit()
        
        self.logger.info(
            "Scan job created",
            job_id=job.job_id,
            domain=domain.domain,
            scan_type=scan_type
        )
        
        return job
    
    async def start_job(
        self,
        session: AsyncSession,
        job_id: str
    ) -> bool:
        """
        Start a scan job
        
        Args:
            session: Database session
            job_id: Job ID to start
        
        Returns:
            True if started successfully
        """
        # Get job
        result = await session.execute(
            select(ScanJob).where(ScanJob.job_id == job_id)
        )
        job = result.scalar_one_or_none()
        
        if not job:
            self.logger.error("Job not found", job_id=job_id)
            return False
        
        if job.status != "pending":
            self.logger.error("Job not in pending state", job_id=job_id, status=job.status)
            return False
        
        # Update job status
        job.status = "running"
        job.started_at = datetime.utcnow()
        await session.commit()
        
        # Create task for job execution
        task = asyncio.create_task(self._execute_job(job_id))
        self.active_jobs[job_id] = task
        
        self.logger.info("Scan job started", job_id=job_id)
        return True
    
    async def _execute_job(self, job_id: str):
        """
        Execute a scan job with per-phase error boundaries
        Runs through all phases based on configuration
        """
        job_errors = []
        phase_results = {}
        
        try:
            # Get job and domain info
            async with self.scanner_engine.db_manager.get_session() as session:
                result = await session.execute(
                    select(ScanJob).where(ScanJob.job_id == job_id)
                )
                job = result.scalar_one_or_none()
                
                if not job:
                    return
                
                domain = await session.get(Domain, job.domain_id)
                if not domain:
                    raise ValueError("Domain not found")
                
                domain_name = domain.domain
                domain_id = job.domain_id
                scan_type = job.scan_type
                config = json.loads(job.configuration) if job.configuration else {}
            
            self.logger.info(
                "Executing scan job",
                job_id=job_id,
                domain=domain_name,
                scan_type=scan_type
            )
            
            # Initialize deduplication manager from database
            async with self.scanner_engine.db_manager.get_session() as session:
                await self.scanner_engine.dedup_manager.initialize_from_database(
                    session,
                    domain_id
                )
            
            # Phase 1: Horizontal Enumeration
            if scan_type in ["full", "subdomain"]:
                phase_results["horizontal"] = await self._run_phase(
                    job_id,
                    "horizontal_enumeration",
                    10,
                    lambda session: self.scanner_engine.run_horizontal_enumeration(
                        session, domain_name, domain_id
                    ),
                    job_errors
                )
            
            # Phase 2: Passive Enumeration
            if scan_type in ["full", "subdomain"]:
                phase_results["passive"] = await self._run_phase(
                    job_id,
                    "passive_enumeration",
                    30,
                    lambda session: self.scanner_engine.run_passive_enumeration(
                        session, domain_name, domain_id
                    ),
                    job_errors
                )
                
                # Update subdomain count
                if phase_results["passive"]:
                    async with self.scanner_engine.db_manager.get_session() as session:
                        result = await session.execute(
                            select(ScanJob).where(ScanJob.job_id == job_id)
                        )
                        job = result.scalar_one_or_none()
                        if job:
                            job.subdomains_found = len(phase_results["passive"])
            
            # Phase 3: Active Enumeration
            if scan_type in ["full", "subdomain"]:
                # Get known subdomains for permutation
                async with self.scanner_engine.db_manager.get_session() as session:
                    result = await session.execute(
                        select(Subdomain.subdomain).where(
                            Subdomain.domain_id == domain_id
                        )
                    )
                    known_subdomains = [row[0] for row in result.fetchall()]
                
                phase_results["active"] = await self._run_phase(
                    job_id,
                    "active_enumeration",
                    50,
                    lambda session: self.scanner_engine.run_active_enumeration(
                        session, domain_name, domain_id, known_subdomains
                    ),
                    job_errors
                )
                
                # Update subdomain count
                if phase_results["active"]:
                    async with self.scanner_engine.db_manager.get_session() as session:
                        result = await session.execute(
                            select(ScanJob).where(ScanJob.job_id == job_id)
                        )
                        job = result.scalar_one_or_none()
                        if job:
                            job.subdomains_found += len(phase_results["active"])
            
            # Phase 4: Web Probing
            if scan_type in ["full", "web"]:
                phase_results["web_probing"] = await self._run_phase(
                    job_id,
                    "web_probing",
                    70,
                    lambda session: self.scanner_engine.run_web_probing(
                        session, domain_id
                    ),
                    job_errors
                )
            
            # Phase 5: Recursive Enumeration (if enabled)
            if config.get("enable_recursion") and scan_type in ["full", "subdomain"]:
                max_depth = config.get("recursion_depth", 2)
                phase_results["recursive"] = await self._run_phase(
                    job_id,
                    "recursive_enumeration",
                    85,
                    lambda session: self.scanner_engine.run_recursive_enumeration(
                        session, domain_id, max_depth
                    ),
                    job_errors
                )
            
            # Mark job as completed
            async with self.scanner_engine.db_manager.get_session() as session:
                result = await session.execute(
                    select(ScanJob).where(ScanJob.job_id == job_id)
                )
                job = result.scalar_one_or_none()
                if job:
                    job.status = "completed" if len(job_errors) == 0 else "partial"
                    job.progress = 100
                    job.completed_at = datetime.utcnow()
                    if job_errors:
                        job.errors = json.dumps(job_errors)
            
            self.logger.info(
                "Scan job completed",
                job_id=job_id,
                status="completed" if len(job_errors) == 0 else "partial",
                errors=len(job_errors)
            )
        
        except Exception as e:
            self.logger.error("Scan job failed", job_id=job_id, error=str(e))
            
            # Update job status
            try:
                async with self.scanner_engine.db_manager.get_session() as session:
                    result = await session.execute(
                        select(ScanJob).where(ScanJob.job_id == job_id)
                    )
                    job = result.scalar_one_or_none()
                    if job:
                        job.status = "failed"
                        job.errors = json.dumps(job_errors + [str(e)])
                        job.completed_at = datetime.utcnow()
            except Exception:
                pass
        
        finally:
            # Remove from active jobs
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]
    
    async def _run_phase(
        self,
        job_id: str,
        phase_name: str,
        progress: int,
        phase_func,
        error_list: List[str]
    ):
        """
        Run a single scan phase with independent transaction and error handling
        
        Args:
            job_id: Job ID
            phase_name: Name of the phase
            progress: Progress percentage
            phase_func: Async function that executes the phase
            error_list: List to append errors to
        
        Returns:
            Phase results or None if failed
        """
        self.logger.info(f"Starting phase: {phase_name}", job_id=job_id)
        
        try:
            # Update job status
            async with self.scanner_engine.db_manager.get_session() as session:
                result = await session.execute(
                    select(ScanJob).where(ScanJob.job_id == job_id)
                )
                job = result.scalar_one_or_none()
                if job:
                    job.current_phase = phase_name
                    job.progress = progress
            
            # Execute phase with its own session
            async with self.scanner_engine.db_manager.get_session() as session:
                result = await phase_func(session)
            
            self.logger.info(f"Phase completed: {phase_name}", job_id=job_id)
            return result
        
        except Exception as e:
            error_msg = f"{phase_name}: {str(e)}"
            error_list.append(error_msg)
            self.logger.error(
                f"Phase failed: {phase_name}",
                job_id=job_id,
                error=str(e)
            )
            return None
    
    async def cancel_job(
        self,
        session: AsyncSession,
        job_id: str
    ) -> bool:
        """
        Cancel a running job
        
        Args:
            session: Database session
            job_id: Job ID to cancel
        
        Returns:
            True if canceled successfully
        """
        # Get job
        result = await session.execute(
            select(ScanJob).where(ScanJob.job_id == job_id)
        )
        job = result.scalar_one_or_none()
        
        if not job:
            return False
        
        # Cancel task if running
        if job_id in self.active_jobs:
            task = self.active_jobs[job_id]
            task.cancel()
            del self.active_jobs[job_id]
        
        # Update job status
        job.status = "cancelled"
        job.completed_at = datetime.utcnow()
        await session.commit()
        
        self.logger.info("Scan job cancelled", job_id=job_id)
        return True
    
    async def get_job_status(
        self,
        session: AsyncSession,
        job_id: str
    ) -> Optional[Dict]:
        """Get job status and progress"""
        result = await session.execute(
            select(ScanJob).where(ScanJob.job_id == job_id)
        )
        job = result.scalar_one_or_none()
        
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "status": job.status,
            "progress": job.progress,
            "current_phase": job.current_phase,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "subdomains_found": job.subdomains_found,
            "ips_discovered": job.ips_discovered,
            "ports_found": job.ports_found,
            "vulnerabilities_identified": job.vulnerabilities_identified
        }

