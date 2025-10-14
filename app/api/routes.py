"""
API routes for scan management and results retrieval
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict
from sqlalchemy import select, func
from datetime import datetime

from app.models.domain import Domain, Subdomain
from app.models.network import IPAddress, Port, ASN, SubdomainIP
from app.models.company import Company
from app.models.scan import ScanJob

router = APIRouter()

# Import interception routes
from app.api.interception_routes import router as interception_router
router.include_router(interception_router)

# Dependency to get scanner engine and db
def get_scanner_engine():
    from main import app_state
    return app_state["scanner_engine"]

def get_job_manager():
    from main import app_state
    return app_state["job_manager"]

async def get_session():
    from main import app_state
    async with app_state["db_manager"].get_session() as session:
        yield session


# Request/Response models
class StartScanRequest(BaseModel):
    domain_id: int
    scan_type: str = "full"
    scan_profile: str = "normal"
    enable_recursion: bool = False
    recursion_depth: int = 2


class CreateDomainRequest(BaseModel):
    domain: str
    is_authorized: bool = False
    scan_profile: str = "passive"
    notes: Optional[str] = None


# Scan Management Endpoints
@router.post("/scans/start")
async def start_scan(
    request: StartScanRequest,
    session = Depends(get_session),
    job_manager = Depends(get_job_manager)
):
    """Start a new scan job"""
    try:
        # Create job
        job = await job_manager.create_job(
            session,
            domain_id=request.domain_id,
            scan_type=request.scan_type,
            scan_profile=request.scan_profile,
            enable_recursion=request.enable_recursion,
            recursion_depth=request.recursion_depth
        )
        
        # Start job
        success = await job_manager.start_job(session, job.job_id)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to start job")
        
        return {
            "job_id": job.job_id,
            "status": "running",
            "message": "Scan started successfully"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{job_id}")
async def get_scan_status(
    job_id: str,
    session = Depends(get_session),
    job_manager = Depends(get_job_manager)
):
    """Get scan job status"""
    status = await job_manager.get_job_status(session, job_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return status


@router.get("/scans/{job_id}/results")
async def get_scan_results(
    job_id: str,
    session = Depends(get_session)
):
    """Get comprehensive scan results"""
    # Get job
    result = await session.execute(
        select(ScanJob).where(ScanJob.job_id == job_id)
    )
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get subdomains
    result = await session.execute(
        select(Subdomain).where(Subdomain.domain_id == job.domain_id)
    )
    subdomains = result.scalars().all()
    
    return {
        "job_id": job.job_id,
        "status": job.status,
        "subdomains_found": job.subdomains_found,
        "subdomains": [
            {
                "subdomain": sub.subdomain,
                "resolves": sub.resolves,
                "has_http": sub.has_http,
                "has_https": sub.has_https,
                "title": sub.title,
                "technologies": sub.technologies
            }
            for sub in subdomains
        ]
    }


@router.delete("/scans/{job_id}")
async def cancel_scan(
    job_id: str,
    session = Depends(get_session),
    job_manager = Depends(get_job_manager)
):
    """Cancel a running scan"""
    success = await job_manager.cancel_job(session, job_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Job not found or already completed")
    
    return {"message": "Scan cancelled"}


@router.get("/scans")
async def list_scans(
    session = Depends(get_session),
    limit: int = 50,
    offset: int = 0
):
    """List all scans"""
    result = await session.execute(
        select(ScanJob)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    jobs = result.scalars().all()
    
    return {
        "scans": [
            {
                "job_id": job.job_id,
                "domain_id": job.domain_id,
                "status": job.status,
                "scan_type": job.scan_type,
                "progress": job.progress,
                "created_at": job.created_at.isoformat() if job.created_at else None
            }
            for job in jobs
        ],
        "total": len(jobs)
    }


# Domain Management Endpoints
@router.get("/domains")
async def list_domains(
    session = Depends(get_session),
    limit: int = 50,
    offset: int = 0
):
    """List all domains"""
    result = await session.execute(
        select(Domain)
        .order_by(Domain.added_at.desc())
        .limit(limit)
        .offset(offset)
    )
    domains = result.scalars().all()
    
    return {
        "domains": [
            {
                "id": domain.id,
                "domain": domain.domain,
                "is_authorized": domain.is_authorized,
                "scan_profile": domain.scan_profile,
                "added_at": domain.added_at.isoformat() if domain.added_at else None,
                "last_scanned": domain.last_scanned.isoformat() if domain.last_scanned else None
            }
            for domain in domains
        ]
    }


@router.post("/domains")
async def create_domain(
    request: CreateDomainRequest,
    session = Depends(get_session)
):
    """Add a new domain"""
    # Check if domain already exists
    result = await session.execute(
        select(Domain).where(Domain.domain == request.domain)
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(status_code=400, detail="Domain already exists")
    
    # Create domain
    domain = Domain(
        domain=request.domain,
        is_authorized=request.is_authorized,
        scan_profile=request.scan_profile,
        notes=request.notes
    )
    session.add(domain)
    await session.commit()
    
    return {
        "id": domain.id,
        "domain": domain.domain,
        "message": "Domain created successfully"
    }


@router.get("/domains/{domain_id}")
async def get_domain(
    domain_id: int,
    session = Depends(get_session)
):
    """Get domain details"""
    domain = await session.get(Domain, domain_id)
    
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Get subdomain count
    result = await session.execute(
        select(func.count(Subdomain.id)).where(Subdomain.domain_id == domain_id)
    )
    subdomain_count = result.scalar()
    
    return {
        "id": domain.id,
        "domain": domain.domain,
        "is_authorized": domain.is_authorized,
        "scan_profile": domain.scan_profile,
        "added_at": domain.added_at.isoformat() if domain.added_at else None,
        "last_scanned": domain.last_scanned.isoformat() if domain.last_scanned else None,
        "scan_count": domain.scan_count,
        "subdomain_count": subdomain_count,
        "notes": domain.notes
    }


@router.get("/domains/{domain_id}/subdomains")
async def get_subdomains(
    domain_id: int,
    session = Depends(get_session),
    limit: int = 100,
    offset: int = 0,
    resolves_only: bool = False
):
    """List subdomains for a domain"""
    query = select(Subdomain).where(Subdomain.domain_id == domain_id)
    
    if resolves_only:
        query = query.where(Subdomain.resolves == True)
    
    query = query.limit(limit).offset(offset)
    
    result = await session.execute(query)
    subdomains = result.scalars().all()
    
    return {
        "subdomains": [
            {
                "id": sub.id,
                "subdomain": sub.subdomain,
                "resolves": sub.resolves,
                "discovery_method": sub.discovery_method,
                "has_http": sub.has_http,
                "has_https": sub.has_https,
                "title": sub.title
            }
            for sub in subdomains
        ]
    }


@router.get("/domains/{domain_id}/ips")
async def get_domain_ips(
    domain_id: int,
    session = Depends(get_session)
):
    """List discovered IPs for a domain"""
    # Get IPs through subdomains
    result = await session.execute(
        select(IPAddress)
        .join(IPAddress.subdomain_associations)
        .join(Subdomain)
        .where(Subdomain.domain_id == domain_id)
        .distinct()
    )
    ips = result.scalars().all()
    
    return {
        "ips": [
            {
                "ip": ip.ip,
                "asn": ip.asn,
                "asn_org": ip.asn_org,
                "cloud_provider": ip.cloud_provider
            }
            for ip in ips
        ]
    }


@router.get("/domains/{domain_id}/ports")
async def get_domain_ports(
    domain_id: int,
    session = Depends(get_session)
):
    """List open ports for a domain"""
    result = await session.execute(
        select(Port)
        .join(IPAddress)
        .join(IPAddress.subdomain_associations)
        .join(Subdomain)
        .where(Subdomain.domain_id == domain_id)
        .where(Port.state == "open")
    )
    ports = result.scalars().all()
    
    return {
        "ports": [
            {
                "ip": port.ip_address.ip,
                "port": port.port,
                "service_name": port.service_name,
                "service_version": port.service_version
            }
            for port in ports
        ]
    }


# Company & ASN Endpoints
@router.get("/companies")
async def list_companies(
    session = Depends(get_session),
    limit: int = 50
):
    """List discovered companies"""
    result = await session.execute(
        select(Company).limit(limit)
    )
    companies = result.scalars().all()
    
    return {
        "companies": [
            {
                "id": company.id,
                "name": company.name,
                "website": company.website
            }
            for company in companies
        ]
    }


@router.get("/asn")
async def list_asns(
    session = Depends(get_session),
    limit: int = 50
):
    """List discovered ASNs"""
    result = await session.execute(
        select(ASN).limit(limit)
    )
    asns = result.scalars().all()
    
    return {
        "asns": [
            {
                "asn_number": asn.asn_number,
                "organization": asn.organization,
                "ip_ranges": asn.ip_ranges
            }
            for asn in asns
        ]
    }


# Analytics Endpoints
@router.get("/analytics/summary")
async def get_analytics_summary(
    session = Depends(get_session)
):
    """Get overall statistics"""
    # Count domains
    result = await session.execute(select(func.count(Domain.id)))
    domain_count = result.scalar()
    
    # Count subdomains
    result = await session.execute(select(func.count(Subdomain.id)))
    subdomain_count = result.scalar()
    
    # Count IPs
    result = await session.execute(select(func.count(IPAddress.id)))
    ip_count = result.scalar()
    
    # Count ports
    result = await session.execute(select(func.count(Port.id)))
    port_count = result.scalar()
    
    return {
        "domains": domain_count,
        "subdomains": subdomain_count,
        "ips": ip_count,
        "ports": port_count
    }


# Infrastructure Graph Endpoint
@router.get("/domains/{domain_id}/graph")
async def get_domain_graph(
    domain_id: int,
    session = Depends(get_session),
    include_ips: bool = True,
    include_ports: bool = False,
    resolves_only: bool = True
):
    """Get infrastructure graph data for visualization"""
    # Get domain
    domain = await session.get(Domain, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Initialize nodes and edges
    nodes = []
    edges = []

    # Add root domain node
    nodes.append({
        "id": f"domain-{domain.id}",
        "label": domain.domain,
        "type": "domain",
        "data": {
            "id": domain.id,
            "domain": domain.domain,
            "is_authorized": domain.is_authorized,
            "scan_profile": domain.scan_profile,
            "last_scanned": domain.last_scanned.isoformat() if domain.last_scanned else None
        }
    })

    # Get subdomains
    query = select(Subdomain).where(Subdomain.domain_id == domain_id)
    if resolves_only:
        query = query.where(Subdomain.resolves == True)

    result = await session.execute(query)
    subdomains = result.scalars().all()

    # Add subdomain nodes and edges
    for subdomain in subdomains:
        node_id = f"subdomain-{subdomain.id}"
        nodes.append({
            "id": node_id,
            "label": subdomain.subdomain,
            "type": "subdomain",
            "data": {
                "id": subdomain.id,
                "subdomain": subdomain.subdomain,
                "resolves": subdomain.resolves,
                "has_http": subdomain.has_http,
                "has_https": subdomain.has_https,
                "title": subdomain.title,
                "status_code": subdomain.status_code,
                "technologies": subdomain.technologies,
                "discovery_method": subdomain.discovery_method
            }
        })

        # Add edge from domain to subdomain
        edges.append({
            "id": f"edge-domain-{domain.id}-subdomain-{subdomain.id}",
            "source": f"domain-{domain.id}",
            "target": node_id,
            "type": "contains"
        })

    # Get IPs and their relationships if requested
    if include_ips:
        # Get all subdomain-IP relationships
        result = await session.execute(
            select(SubdomainIP)
            .join(Subdomain)
            .where(Subdomain.domain_id == domain_id)
        )
        subdomain_ips = result.scalars().all()

        # Track added IPs to avoid duplicates
        added_ips = set()

        for subdomain_ip in subdomain_ips:
            ip_id = f"ip-{subdomain_ip.ip_id}"

            # Add IP node if not already added
            if subdomain_ip.ip_id not in added_ips:
                ip = await session.get(IPAddress, subdomain_ip.ip_id)
                if ip:
                    nodes.append({
                        "id": ip_id,
                        "label": ip.ip,
                        "type": "ip",
                        "data": {
                            "id": ip.id,
                            "ip": ip.ip,
                            "asn": ip.asn,
                            "asn_org": ip.asn_org,
                            "cloud_provider": ip.cloud_provider,
                            "geolocation": ip.geolocation
                        }
                    })
                    added_ips.add(subdomain_ip.ip_id)

                    # Add ASN node if available
                    if ip.asn:
                        asn_id = f"asn-{ip.asn}"
                        # Check if ASN node already exists
                        if not any(n["id"] == asn_id for n in nodes):
                            nodes.append({
                                "id": asn_id,
                                "label": f"AS{ip.asn}",
                                "type": "asn",
                                "data": {
                                    "asn": ip.asn,
                                    "organization": ip.asn_org
                                }
                            })

                        # Add edge from IP to ASN
                        edges.append({
                            "id": f"edge-ip-{ip.id}-asn-{ip.asn}",
                            "source": ip_id,
                            "target": asn_id,
                            "type": "belongs_to"
                        })

            # Add edge from subdomain to IP
            edges.append({
                "id": f"edge-subdomain-{subdomain_ip.subdomain_id}-ip-{subdomain_ip.ip_id}",
                "source": f"subdomain-{subdomain_ip.subdomain_id}",
                "target": ip_id,
                "type": "resolves_to"
            })

        # Get open ports if requested
        if include_ports:
            result = await session.execute(
                select(Port)
                .join(IPAddress)
                .join(IPAddress.subdomain_associations)
                .join(Subdomain)
                .where(Subdomain.domain_id == domain_id)
                .where(Port.state == "open")
            )
            ports = result.scalars().all()

            for port in ports:
                port_id = f"port-{port.id}"
                nodes.append({
                    "id": port_id,
                    "label": f"{port.port}/{port.protocol or 'tcp'}",
                    "type": "port",
                    "data": {
                        "id": port.id,
                        "port": port.port,
                        "protocol": port.protocol,
                        "state": port.state,
                        "service_name": port.service_name,
                        "service_version": port.service_version
                    }
                })

                # Add edge from IP to Port
                edges.append({
                    "id": f"edge-ip-{port.ip_id}-port-{port.id}",
                    "source": f"ip-{port.ip_id}",
                    "target": port_id,
                    "type": "has_port"
                })

    return {
        "domain_id": domain_id,
        "nodes": nodes,
        "edges": edges,
        "statistics": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "subdomains": len([n for n in nodes if n["type"] == "subdomain"]),
            "ips": len([n for n in nodes if n["type"] == "ip"]),
            "asns": len([n for n in nodes if n["type"] == "asn"]),
            "ports": len([n for n in nodes if n["type"] == "port"])
        }
    }

