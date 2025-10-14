"""
Main application entry point
Initializes the platform and starts the web server
"""

import asyncio
import argparse
import sys
from pathlib import Path
from contextlib import asynccontextmanager
import structlog
import uvicorn
from fastapi.responses import JSONResponse
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.config import ApplicationConfig
from app.core.database import DatabaseManager
from app.core.logging import configure_logging
from app.scanner.engine import ScannerEngine
from app.scanner.job_manager import ScanJobManager
from app.scanner.tools.installer import ToolInstaller
from app.api.routes import router as api_router
from app.api.pattern_routes import router as pattern_router
from app.api.websocket_routes import router as ws_router
from app.api.websocket import ws_manager
from app.cli.tool_manager import (
    install_tools_command,
    check_tools_command,
    install_tool_command,
    download_resources_command,
    show_tool_guide
)
from app.cli.api_key_manager import (
    set_api_key_command,
    list_api_keys_command,
    remove_api_key_command,
    test_api_key_command
)

# Configure logging first
configure_logging()
logger = structlog.get_logger()

# Global application state
app_state = {
    "config": None,
    "db_manager": None,
    "scanner_engine": None,
    "job_manager": None,
    "tool_installer": None,
    "ws_manager": ws_manager
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""

    # Startup
    logger.info("Starting Security Reconnaissance Platform")

    # Initialize configuration
    app_state["config"] = ApplicationConfig()
    logger.info("Configuration loaded", 
                scan_profile=app_state["config"].scanner.scan_profile)

    # Initialize database
    app_state["db_manager"] = DatabaseManager(app_state["config"].database)
    await app_state["db_manager"].initialize()
    
    # Initialize tool installer
    app_state["tool_installer"] = ToolInstaller(
        app_state["config"].tools.tools_directory
    )
    
    # Check tool availability
    tool_status = app_state["tool_installer"].get_tool_status()
    available_tools = sum(1 for status in tool_status.values() if status.get("available"))
    logger.info(
        "Tool status checked",
        available=available_tools,
        total=len(tool_status)
    )
    
    # Initialize scanner engine
    app_state["scanner_engine"] = ScannerEngine(
        app_state["config"],
        app_state["db_manager"]
    )
    
    # Initialize job manager
    app_state["job_manager"] = ScanJobManager(
        app_state["config"],
        app_state["scanner_engine"]
    )
    
    logger.info("Platform initialized successfully")

    yield

    # Shutdown
    logger.info("Shutting down platform")

    # Close database connections
    if app_state["db_manager"]:
        await app_state["db_manager"].close()

    logger.info("Platform shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="Security Reconnaissance Platform",
    description="Automated vulnerability discovery through intelligent reconnaissance",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS - Allow frontend to access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Vite default
        "http://localhost:3001",  # Alternative port
        "http://localhost:5173",  # Vite alternative default
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Include API routers
app.include_router(api_router, prefix="/api", tags=["api"])
app.include_router(pattern_router)
app.include_router(ws_router, tags=["websocket"])


@app.get("/")
async def root():
    """Root endpoint - platform status"""
    return {
        "platform": "Security Reconnaissance Platform",
        "status": "operational",
        "version": "1.0.0",
        "scan_profile": app_state["config"].scanner.scan_profile if app_state["config"] else "unknown"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connectivity
        if app_state["db_manager"]:
            async with app_state["db_manager"].get_session() as session:
                await session.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
            "config": "loaded"
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )


@app.get("/api/health/comprehensive")
async def comprehensive_health_check():
    """Comprehensive health check including tools, database, and configuration"""
    health_status = {
        "status": "healthy",
        "timestamp": asyncio.get_event_loop().time(),
        "components": {}
    }
    
    issues = []
    
    # Database check
    try:
        if app_state["db_manager"]:
            async with app_state["db_manager"].get_session() as session:
                await session.execute(text("SELECT 1"))
            health_status["components"]["database"] = {
                "status": "healthy",
                "type": "connected"
            }
        else:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": "Database manager not initialized"
            }
            issues.append("database_not_initialized")
    except Exception as e:
        health_status["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        issues.append("database_connection_failed")
    
    # Configuration check
    try:
        health_status["components"]["configuration"] = {
            "status": "healthy",
            "scan_profile": app_state["config"].scanner.scan_profile if app_state["config"] else "unknown",
            "rate_limit": app_state["config"].security.global_rate_limit if app_state["config"] else None
        }
    except Exception as e:
        health_status["components"]["configuration"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        issues.append("configuration_error")
    
    # Tool availability check
    try:
        if app_state["tool_installer"]:
            tool_status = app_state["tool_installer"].get_tool_status()
            available_count = sum(1 for status in tool_status.values() if status.get("available"))
            total_count = len(tool_status)
            
            critical_tools = ["go", "git", "python3"]
            critical_available = all(
                tool_status.get(tool, {}).get("available", False)
                for tool in critical_tools
            )
            
            health_status["components"]["tools"] = {
                "status": "healthy" if critical_available else "degraded",
                "available": available_count,
                "total": total_count,
                "percentage": round((available_count / total_count * 100), 1) if total_count > 0 else 0,
                "critical_tools_available": critical_available
            }
            
            if not critical_available:
                issues.append("critical_tools_missing")
            if available_count < total_count * 0.5:
                issues.append("many_tools_missing")
        else:
            health_status["components"]["tools"] = {
                "status": "unknown",
                "error": "Tool installer not initialized"
            }
    except Exception as e:
        health_status["components"]["tools"] = {
            "status": "error",
            "error": str(e)
        }
        issues.append("tool_check_failed")
    
    # Scanner engine check
    try:
        health_status["components"]["scanner"] = {
            "status": "healthy" if app_state["scanner_engine"] else "unhealthy",
            "initialized": app_state["scanner_engine"] is not None
        }
        if not app_state["scanner_engine"]:
            issues.append("scanner_not_initialized")
    except Exception as e:
        health_status["components"]["scanner"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        issues.append("scanner_check_failed")
    
    # Job manager check
    try:
        health_status["components"]["job_manager"] = {
            "status": "healthy" if app_state["job_manager"] else "unhealthy",
            "initialized": app_state["job_manager"] is not None
        }
        if not app_state["job_manager"]:
            issues.append("job_manager_not_initialized")
    except Exception as e:
        health_status["components"]["job_manager"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        issues.append("job_manager_check_failed")
    
    # API Keys check (optional)
    try:
        if app_state["config"]:
            api_key_services = app_state["config"].api_keys.list_services()
            health_status["components"]["api_keys"] = {
                "status": "info",
                "configured_services": len(api_key_services),
                "note": "API keys are optional"
            }
    except Exception as e:
        health_status["components"]["api_keys"] = {
            "status": "info",
            "error": str(e),
            "note": "API keys are optional"
        }
    
    # Determine overall status
    if issues:
        health_status["issues"] = issues
        if any(issue in ["database_connection_failed", "scanner_not_initialized"] for issue in issues):
            health_status["status"] = "unhealthy"
            status_code = 503
        else:
            health_status["status"] = "degraded"
            status_code = 200
    else:
        health_status["status"] = "healthy"
        status_code = 200
    
    # Add recommendations
    recommendations = []
    if "critical_tools_missing" in issues or "many_tools_missing" in issues:
        recommendations.append("Run 'python main.py --install-tools' to install missing security tools")
    if len(health_status["components"].get("api_keys", {}).get("configured_services", 0)) == 0:
        recommendations.append("Consider configuring API keys for enhanced features (optional)")
    
    if recommendations:
        health_status["recommendations"] = recommendations
    
    return JSONResponse(
        status_code=status_code,
        content=health_status
    )


@app.post("/api/config/api-keys/{service}")
async def store_api_key(service: str, request: Request):
    """Store an encrypted API key for a service"""
    data = await request.json()
    api_key = data.get("api_key")

    if not api_key:
        return JSONResponse(
            status_code=400,
            content={"error": "API key required"}
        )

    app_state["config"].api_keys.save_key(service, api_key)
    return {"message": f"API key for {service} stored successfully"}


@app.get("/api/config/api-keys")
async def list_api_keys():
    """List all services with stored API keys"""
    services = app_state["config"].api_keys.list_services()
    return {"services": services}


@app.post("/api/tools/install")
async def install_tools():
    """Install all external security tools"""
    if not app_state["tool_installer"]:
        return JSONResponse(
            status_code=503,
            content={"error": "Tool installer not initialized"}
        )
    
    logger.info("Starting tool installation")
    results = await app_state["tool_installer"].install_all()
    
    return {
        "message": "Tool installation complete",
        "results": results,
        "available": sum(1 for v in results.values() if v),
        "total": len(results)
    }


@app.get("/api/tools/status")
async def get_tool_status():
    """Get status of all external tools"""
    if not app_state["tool_installer"]:
        return JSONResponse(
            status_code=503,
            content={"error": "Tool installer not initialized"}
        )
    
    status = app_state["tool_installer"].get_tool_status()
    return {"tools": status}


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Security Reconnaissance Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          Start the web server
  python main.py --install-tools          Install all security tools
  python main.py --check-tools            Check tool availability
  python main.py --tool-status            Show detailed tool status
  python main.py --install-tool subfinder Install specific tool
  python main.py --download-resources     Download wordlists and resolvers
  python main.py --tool-guide             Show installation guide
        """
    )
    
    parser.add_argument(
        "--install-tools",
        action="store_true",
        help="Install all external security tools"
    )
    
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Check availability of all tools"
    )
    
    parser.add_argument(
        "--tool-status",
        action="store_true",
        help="Show detailed status of all tools"
    )
    
    parser.add_argument(
        "--install-tool",
        metavar="TOOL",
        help="Install a specific tool by name"
    )
    
    parser.add_argument(
        "--download-resources",
        action="store_true",
        help="Download required resources (wordlists, resolvers)"
    )
    
    parser.add_argument(
        "--tool-guide",
        action="store_true",
        help="Display tool installation guide"
    )
    
    # API Key Management
    parser.add_argument(
        "--set-api-key",
        nargs='+',
        metavar=("SERVICE", "KEY"),
        help="Set an API key for a service"
    )
    
    parser.add_argument(
        "--list-api-keys",
        action="store_true",
        help="List all configured API key services"
    )
    
    parser.add_argument(
        "--remove-api-key",
        metavar="SERVICE",
        help="Remove an API key for a service"
    )
    
    parser.add_argument(
        "--test-api-key",
        metavar="SERVICE",
        help="Test if an API key is configured and valid"
    )
    
    parser.add_argument(
        "--api-key-guide",
        action="store_true",
        help="Display API key configuration guide"
    )
    
    # Server Options
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the web server (default: 127.0.0.1)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the web server (default: 8000)"
    )
    
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Disable hot reload (useful for production)"
    )
    
    return parser.parse_args()


async def run_cli_command(args):
    """Execute CLI commands"""
    # Tool management commands
    if args.install_tools:
        return await install_tools_command()
    elif args.check_tools or args.tool_status:
        return await check_tools_command()
    elif args.install_tool:
        return await install_tool_command(args.install_tool)
    elif args.download_resources:
        return await download_resources_command()
    elif args.tool_guide:
        return show_tool_guide()
    
    # API key management commands
    elif args.set_api_key:
        service = args.set_api_key[0]
        api_key = args.set_api_key[1] if len(args.set_api_key) > 1 else None
        return set_api_key_command(service, api_key)
    elif args.list_api_keys:
        return list_api_keys_command()
    elif args.remove_api_key:
        return remove_api_key_command(args.remove_api_key)
    elif args.test_api_key:
        return test_api_key_command(args.test_api_key)
    elif args.api_key_guide:
        return show_api_key_guide()
    
    return None


if __name__ == "__main__":
    # Parse command line arguments
    args = parse_arguments()
    
    # Create necessary directories
    Path("data").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    Path("config").mkdir(exist_ok=True)
    Path("tools").mkdir(exist_ok=True)
    
    # Check if this is a CLI command
    if any([
        args.install_tools,
        args.check_tools,
        args.tool_status,
        args.install_tool,
        args.download_resources,
        args.tool_guide,
        args.set_api_key,
        args.list_api_keys,
        args.remove_api_key,
        args.test_api_key,
        args.api_key_guide
    ]):
        # Run CLI command
        exit_code = asyncio.run(run_cli_command(args))
        sys.exit(exit_code or 0)
    
    # Otherwise, run the web server
    uvicorn.run(
        "main:app",
        host=args.host,
        port=args.port,
        reload=not args.no_reload,
        log_config=None  # Use our custom logging configuration
    )
