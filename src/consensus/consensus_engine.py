"""
Consensus engine for multi-agent findings
"""
from typing import List, Dict, Any
from collections import defaultdict
import json

class ConsensusEngine:
    """Build consensus from multiple agent findings"""
    
    def __init__(self, min_agreement: int = 2, similarity_threshold: float = 0.85):
        self.min_agreement = min_agreement
        self.similarity_threshold = similarity_threshold
    
    def build_consensus(
        self,
        agent_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Build consensus from multiple agent results
        
        Args:
            agent_results: List of results from different agents
        
        Returns:
            Consensus findings with confidence scores
        """
        all_findings = []
        
        # Collect all findings
        for result in agent_results:
            agent_name = result.get('agent', 'unknown')
            for finding in result.get('findings', []):
                finding['source_agent'] = agent_name
                all_findings.append(finding)
        
        # Group similar findings
        finding_clusters = self._cluster_findings(all_findings)
        
        # Build consensus findings
        consensus_findings = []
        rejected_findings = []
        
        for cluster in finding_clusters:
            if len(cluster) >= self.min_agreement:
                # Build consensus finding
                consensus = self._build_consensus_finding(cluster)
                consensus_findings.append(consensus)
            else:
                # Rejected - not enough agreement
                for finding in cluster:
                    finding['rejection_reason'] = f"Only {len(cluster)} agent(s) agreed"
                    rejected_findings.append(finding)
        
        return {
            "consensus_findings": consensus_findings,
            "rejected_findings": rejected_findings,
            "total_agents": len(agent_results),
            "agreement_threshold": self.min_agreement,
            "statistics": {
                "total_findings": len(all_findings),
                "consensus_count": len(consensus_findings),
                "rejected_count": len(rejected_findings)
            }
        }
    
    def _cluster_findings(self, findings: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Cluster similar findings together"""
        clusters = []
        used_indices = set()
        
        for i, finding1 in enumerate(findings):
            if i in used_indices:
                continue
            
            cluster = [finding1]
            used_indices.add(i)
            
            for j, finding2 in enumerate(findings):
                if j in used_indices or i == j:
                    continue
                
                if self._are_similar(finding1, finding2):
                    cluster.append(finding2)
                    used_indices.add(j)
            
            clusters.append(cluster)
        
        return clusters
    
    def _are_similar(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> bool:
        """Check if two findings are similar"""
        # Simple similarity based on description and location
        
        # Check CWE overlap
        cwe1 = set(finding1.get('cwe', []))
        cwe2 = set(finding2.get('cwe', []))
        
        if cwe1 and cwe2:
            cwe_overlap = len(cwe1 & cwe2) / len(cwe1 | cwe2)
            if cwe_overlap > 0.5:
                return True
        
        # Check file path
        target1 = finding1.get('target', {})
        target2 = finding2.get('target', {})
        
        if target1.get('file_path') == target2.get('file_path'):
            # Same file - check line numbers
            line1 = target1.get('start_line', 0)
            line2 = target2.get('start_line', 0)
            
            if abs(line1 - line2) < 5:  # Within 5 lines
                return True
        
        # Check description similarity (basic)
        desc1 = finding1.get('finding_description', '').lower()
        desc2 = finding2.get('finding_description', '').lower()
        
        common_words = set(desc1.split()) & set(desc2.split())
        if len(common_words) > 3:
            return True
        
        return False
    
    def _build_consensus_finding(self, cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build a consensus finding from a cluster"""
        # Use the finding with highest confidence as base
        base_finding = max(cluster, key=lambda f: f.get('confidence', 0.5))
        
        # Aggregate information
        source_agents = [f['source_agent'] for f in cluster]
        avg_confidence = sum(f.get('confidence', 0.5) for f in cluster) / len(cluster)
        
        consensus = base_finding.copy()
        consensus['consensus_info'] = {
            'source_agents': source_agents,
            'agreement_count': len(cluster),
            'consensus_confidence': round(avg_confidence, 2),
            'verified': True
        }
        
        return consensus
    
    def generate_report(self, consensus_result: Dict[str, Any]) -> str:
        """Generate human-readable report"""
        report = []
        report.append("=" * 80)
        report.append("AI SECURITY SCANNER - CONSENSUS REPORT")
        report.append("=" * 80)
        report.append("")
        
        stats = consensus_result['statistics']
        report.append(f"Total Agents: {consensus_result['total_agents']}")
        report.append(f"Total Findings: {stats['total_findings']}")
        report.append(f"Consensus Findings: {stats['consensus_count']}")
        report.append(f"Rejected Findings: {stats['rejected_count']}")
        report.append("")
        
        report.append("=" * 80)
        report.append("VERIFIED FINDINGS (Multi-Agent Consensus)")
        report.append("=" * 80)
        report.append("")
        
        for i, finding in enumerate(consensus_result['consensus_findings'], 1):
            consensus_info = finding.get('consensus_info', {})
            
            report.append(f"{i}. {finding.get('finding_description', 'Unknown')}")
            report.append(f"   Severity: {finding.get('severity', 'Unknown')}")
            report.append(f"   CVSS Score: {finding.get('cvss_score', 'N/A')}")
            report.append(f"   CWE: {', '.join(finding.get('cwe', []))}")
            report.append(f"   Agreed by: {', '.join(consensus_info.get('source_agents', []))}")
            report.append(f"   Confidence: {consensus_info.get('consensus_confidence', 0):.2f}")
            
            target = finding.get('target', {})
            if target:
                report.append(f"   Location: {target.get('file_path', 'Unknown')} "
                            f"(lines {target.get('start_line', '?')}-{target.get('end_line', '?')})")
            
            report.append("")
        
        return "\n".join(report)