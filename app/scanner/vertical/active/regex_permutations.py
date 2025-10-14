"""
Regex-based subdomain permutation generation
Learns patterns from discovered subdomains and generates intelligent variations
"""

from typing import List, Set
import structlog
import re
from collections import Counter

logger = structlog.get_logger()


class RegexPermuter:
    """
    Generates subdomain permutations based on discovered patterns
    Uses regex analysis to identify common patterns and generate variations
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="regex_permutations")
        
        # Common patterns to look for
        self.common_separators = ['-', '_', '.']
        self.common_suffixes = ['dev', 'prod', 'staging', 'test', 'qa', 'uat', 'demo']
        self.common_prefixes = ['api', 'www', 'mail', 'ftp', 'admin', 'portal']
        self.version_patterns = ['v1', 'v2', 'v3', '01', '02', '03']
        self.environment_keywords = ['development', 'production', 'stage', 'testing']
    
    def generate_permutations(
        self,
        subdomains: List[str],
        base_domain: str
    ) -> List[str]:
        """
        Generate permutations based on patterns found in discovered subdomains
        
        Args:
            subdomains: List of discovered subdomains
            base_domain: Base domain for filtering
        
        Returns:
            List of generated subdomain permutations
        """
        if not subdomains:
            return []
        
        self.logger.info("Analyzing patterns", subdomains=len(subdomains))
        
        permutations = set()
        
        # Analyze patterns
        patterns = self._analyze_patterns(subdomains, base_domain)
        
        # Generate permutations based on identified patterns
        for subdomain in subdomains:
            # Remove base domain
            if subdomain.endswith(f".{base_domain}"):
                prefix = subdomain[:-len(f".{base_domain}")]
            else:
                prefix = subdomain
            
            # Apply various permutation strategies
            permutations.update(self._version_permutations(prefix, base_domain))
            permutations.update(self._environment_permutations(prefix, base_domain))
            permutations.update(self._separator_permutations(prefix, base_domain))
            permutations.update(self._numeric_permutations(prefix, base_domain))
            permutations.update(self._prefix_suffix_permutations(prefix, base_domain, patterns))
        
        self.logger.info(
            "Generated permutations",
            total=len(permutations)
        )
        
        return list(permutations)
    
    def _analyze_patterns(
        self,
        subdomains: List[str],
        base_domain: str
    ) -> dict:
        """Analyze common patterns in subdomains"""
        patterns = {
            "separators": Counter(),
            "suffixes": Counter(),
            "prefixes": Counter(),
            "has_numbers": 0,
            "has_versions": 0
        }
        
        for subdomain in subdomains:
            if subdomain.endswith(f".{base_domain}"):
                prefix = subdomain[:-len(f".{base_domain}")]
            else:
                prefix = subdomain
            
            # Count separators
            for sep in self.common_separators:
                if sep in prefix:
                    patterns["separators"][sep] += 1
            
            # Check for numbers
            if re.search(r'\d', prefix):
                patterns["has_numbers"] += 1
            
            # Check for version patterns
            if re.search(r'v\d+', prefix, re.IGNORECASE):
                patterns["has_versions"] += 1
            
            # Extract potential prefixes and suffixes
            parts = re.split(r'[-_.]', prefix)
            if len(parts) > 1:
                patterns["prefixes"][parts[0]] += 1
                patterns["suffixes"][parts[-1]] += 1
        
        return patterns
    
    def _version_permutations(
        self,
        prefix: str,
        base_domain: str
    ) -> Set[str]:
        """Generate version-based permutations"""
        perms = set()
        
        # If has version, try other versions
        version_match = re.search(r'v(\d+)', prefix, re.IGNORECASE)
        if version_match:
            current_version = int(version_match.group(1))
            base = prefix[:version_match.start()] + prefix[version_match.end():]
            
            for v in range(1, min(current_version + 3, 6)):  # Try v1-v5
                perms.add(f"{base}v{v}.{base_domain}")
                perms.add(f"v{v}{base}.{base_domain}")
        else:
            # Add version suffixes/prefixes
            for version in ['v1', 'v2', 'v3']:
                perms.add(f"{prefix}{version}.{base_domain}")
                perms.add(f"{version}{prefix}.{base_domain}")
                perms.add(f"{prefix}-{version}.{base_domain}")
        
        return perms
    
    def _environment_permutations(
        self,
        prefix: str,
        base_domain: str
    ) -> Set[str]:
        """Generate environment-based permutations"""
        perms = set()
        
        # Check if already has environment suffix
        has_env = any(env in prefix.lower() for env in self.common_suffixes)
        
        if not has_env:
            # Add environment suffixes
            for env in self.common_suffixes:
                perms.add(f"{prefix}-{env}.{base_domain}")
                perms.add(f"{prefix}.{env}.{base_domain}")
                perms.add(f"{env}-{prefix}.{base_domain}")
                perms.add(f"{env}.{prefix}.{base_domain}")
        
        return perms
    
    def _separator_permutations(
        self,
        prefix: str,
        base_domain: str
    ) -> Set[str]:
        """Generate permutations with different separators"""
        perms = set()
        
        # Replace separators
        for old_sep in self.common_separators:
            if old_sep in prefix:
                for new_sep in self.common_separators:
                    if new_sep != old_sep:
                        new_prefix = prefix.replace(old_sep, new_sep)
                        perms.add(f"{new_prefix}.{base_domain}")
        
        return perms
    
    def _numeric_permutations(
        self,
        prefix: str,
        base_domain: str
    ) -> Set[str]:
        """Generate numeric permutations"""
        perms = set()
        
        # Find numbers in prefix
        numbers = re.findall(r'\d+', prefix)
        
        if numbers:
            for num in numbers:
                num_int = int(num)
                # Try +/- 1, 2
                for offset in [-2, -1, 1, 2]:
                    new_num = num_int + offset
                    if new_num >= 0:
                        new_prefix = prefix.replace(num, str(new_num).zfill(len(num)))
                        perms.add(f"{new_prefix}.{base_domain}")
        else:
            # Add numbers to prefix without numbers
            for num in ['1', '2', '3', '01', '02']:
                perms.add(f"{prefix}{num}.{base_domain}")
                perms.add(f"{prefix}-{num}.{base_domain}")
        
        return perms
    
    def _prefix_suffix_permutations(
        self,
        prefix: str,
        base_domain: str,
        patterns: dict
    ) -> Set[str]:
        """Generate permutations based on common prefixes/suffixes"""
        perms = set()
        
        # Use most common prefixes from patterns
        common_prefixes = [p for p, count in patterns["prefixes"].most_common(5)]
        common_suffixes = [s for s, count in patterns["suffixes"].most_common(5)]
        
        # Add discovered prefixes/suffixes to known ones
        all_prefixes = list(set(self.common_prefixes + common_prefixes))
        all_suffixes = list(set(self.common_suffixes + common_suffixes))
        
        # Generate combinations
        for pref in all_prefixes[:5]:  # Limit to top 5
            perms.add(f"{pref}-{prefix}.{base_domain}")
            perms.add(f"{pref}.{prefix}.{base_domain}")
        
        for suff in all_suffixes[:5]:  # Limit to top 5
            perms.add(f"{prefix}-{suff}.{base_domain}")
            perms.add(f"{prefix}.{suff}.{base_domain}")
        
        return perms
