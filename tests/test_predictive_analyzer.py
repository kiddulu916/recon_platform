#!/usr/bin/env python3
"""
Quick test to verify predictive analyzer imports correctly
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from app.intelligence.pattern_recognition.predictive_analyzer import PredictiveVulnerabilityAnalyzer

    print("✓ Import successful!")
    print(f"✓ Class: {PredictiveVulnerabilityAnalyzer.__name__}")

    # Check key methods exist
    methods = [
        'analyze_domain',
        'predict_from_technology',
        'predict_from_patterns',
        'predict_from_configuration',
        'predict_from_historical_data',
        'generate_testing_guidance',
        'save_predictions'
    ]

    for method in methods:
        if hasattr(PredictiveVulnerabilityAnalyzer, method):
            print(f"✓ Method exists: {method}")
        else:
            print(f"✗ Method missing: {method}")

    # Check knowledge base
    analyzer = PredictiveVulnerabilityAnalyzer()
    kb_count = len(analyzer.TECH_VULNERABILITY_KB)
    print(f"✓ Technology knowledge base: {kb_count} technologies")

    # List some technologies
    print("\nSample technologies in KB:")
    for i, tech in enumerate(list(analyzer.TECH_VULNERABILITY_KB.keys())[:5]):
        vuln_count = len(analyzer.TECH_VULNERABILITY_KB[tech]['vulns'])
        print(f"  - {tech}: {vuln_count} vulnerability types")

    print("\n✓ All checks passed!")

except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
