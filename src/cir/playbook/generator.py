"""Incident response playbook generator using LLM."""
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
try:
    from langchain.llms import Ollama
    from langchain.prompts import PromptTemplate
    from langchain.chains import LLMChain
except ImportError:
    # Fallback for environments without langchain
    Ollama = None
    PromptTemplate = None
    LLMChain = None

from ..core.models import Incident, Playbook, PlaybookStep, SeverityLevel
from ..core.config import config_manager


class PlaybookGenerator:
    """Generates incident response playbooks using LLM."""
    
    def __init__(self):
        self.config = config_manager.get_playbook_config()
        self.llm_config = self.config.get('llm', {})
        self.llm = None
        self._initialize_llm()
    
    def _initialize_llm(self) -> None:
        """Initialize the LLM for playbook generation."""
        if Ollama is None:
            print("Warning: LangChain not available. Using template-based playbook generation.")
            return
        
        try:
            self.llm = Ollama(
                base_url=config_manager.settings.ollama_host,
                model=self.llm_config.get('model', 'llama2'),
                temperature=self.llm_config.get('temperature', 0.3),
            )
            print(f"Initialized LLM: {self.llm_config.get('model', 'llama2')}")
        except Exception as e:
            print(f"Warning: Could not initialize Ollama LLM: {e}")
            print("Using template-based playbook generation instead.")
    
    def generate_playbook(self, incident: Incident) -> Playbook:
        """Generate an incident response playbook for an incident."""
        playbook_id = f"playbook-{uuid.uuid4().hex[:12]}"
        
        # Try LLM-based generation first
        if self.llm:
            try:
                return self._generate_with_llm(playbook_id, incident)
            except Exception as e:
                print(f"Error generating playbook with LLM: {e}")
                print("Falling back to template-based generation")
        
        # Fallback to template-based generation
        return self._generate_from_template(playbook_id, incident)
    
    def _generate_with_llm(self, playbook_id: str, incident: Incident) -> Playbook:
        """Generate playbook using LLM."""
        # Create prompt for LLM
        prompt_template = """You are a cybersecurity incident response expert. Generate a detailed incident response playbook for the following security incident.

Incident Details:
- Title: {title}
- Severity: {severity}
- Description: {description}
- Affected Systems: {systems}
- Affected Users: {users}
- Attack Timeline: {timeline}

Generate a step-by-step incident response playbook with the following structure:
1. Investigation steps
2. Containment steps
3. Eradication steps
4. Recovery steps
5. Post-incident activities

For each step, provide:
- Step title
- Detailed description
- Specific commands or actions to take
- Expected outcome

Format your response as a numbered list with clear sections."""

        prompt = PromptTemplate(
            input_variables=["title", "severity", "description", "systems", "users", "timeline"],
            template=prompt_template
        )
        
        chain = LLMChain(llm=self.llm, prompt=prompt)
        
        # Generate playbook content
        result = chain.run(
            title=incident.title,
            severity=incident.severity.value,
            description=incident.description,
            systems=", ".join(incident.affected_systems) if incident.affected_systems else "Unknown",
            users=", ".join(incident.affected_users) if incident.affected_users else "Unknown",
            timeline=str(incident.attack_timeline)
        )
        
        # Parse LLM output into structured steps
        steps = self._parse_llm_output(result, incident.severity)
        
        return Playbook(
            id=playbook_id,
            incident_id=incident.id,
            created_at=datetime.utcnow(),
            title=f"Incident Response: {incident.title}",
            description=f"Automated playbook for {incident.title}",
            severity=incident.severity,
            steps=steps,
            estimated_duration="2-4 hours",
            prerequisites=["Administrative access", "Log access", "Network tools"],
            references=[
                "NIST SP 800-61 Computer Security Incident Handling Guide",
                "SANS Incident Response Process"
            ]
        )
    
    def _parse_llm_output(self, llm_output: str, severity: SeverityLevel) -> List[PlaybookStep]:
        """Parse LLM output into structured playbook steps."""
        steps = []
        lines = llm_output.split('\n')
        
        current_step = None
        step_number = 1
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detect step headers (numbered or with keywords)
            if any(keyword in line.lower() for keyword in ['step', 'phase', '1.', '2.', '3.']):
                if current_step:
                    steps.append(current_step)
                
                # Determine action type from content
                action_type = "investigate"
                if "contain" in line.lower():
                    action_type = "contain"
                elif "eradicate" in line.lower() or "remove" in line.lower():
                    action_type = "eradicate"
                elif "recover" in line.lower():
                    action_type = "recover"
                
                current_step = PlaybookStep(
                    step_number=step_number,
                    title=line,
                    description="",
                    action_type=action_type,
                    commands=[],
                    expected_outcome="",
                    approval_required=severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
                )
                step_number += 1
            elif current_step:
                # Add to current step description
                current_step.description += line + " "
        
        if current_step:
            steps.append(current_step)
        
        return steps if steps else self._get_default_steps(severity)
    
    def _generate_from_template(self, playbook_id: str, incident: Incident) -> Playbook:
        """Generate playbook from templates (fallback when LLM is unavailable)."""
        steps = self._get_default_steps(incident.severity)
        
        # Customize based on incident details
        if incident.attack_timeline:
            steps.insert(0, PlaybookStep(
                step_number=0,
                title="Review Attack Timeline",
                description=f"Review the attack timeline with {len(incident.attack_timeline)} events to understand the incident progression.",
                action_type="investigate",
                commands=[],
                expected_outcome="Clear understanding of the attack sequence",
                approval_required=False
            ))
        
        return Playbook(
            id=playbook_id,
            incident_id=incident.id,
            created_at=datetime.utcnow(),
            title=f"Incident Response: {incident.title}",
            description=f"Template-based playbook for {incident.severity.value} severity incident",
            severity=incident.severity,
            steps=steps,
            estimated_duration="2-4 hours" if incident.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] else "1-2 hours",
            prerequisites=["Administrative access", "Log access", "Network monitoring tools"],
            references=[
                "NIST SP 800-61 Rev. 2",
                "SANS Incident Handler's Handbook",
                "MITRE ATT&CK Framework"
            ]
        )
    
    def _get_default_steps(self, severity: SeverityLevel) -> List[PlaybookStep]:
        """Get default playbook steps based on severity."""
        require_approval = severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        
        steps = [
            PlaybookStep(
                step_number=1,
                title="Initial Triage and Scope Assessment",
                description="Assess the scope and impact of the incident. Identify affected systems, users, and data.",
                action_type="investigate",
                commands=[
                    "Review all related alerts and logs",
                    "Identify affected systems and user accounts",
                    "Determine the attack vector and entry point"
                ],
                expected_outcome="Clear understanding of incident scope and affected assets",
                approval_required=False
            ),
            PlaybookStep(
                step_number=2,
                title="Evidence Collection and Preservation",
                description="Collect and preserve evidence for forensic analysis and potential legal proceedings.",
                action_type="investigate",
                commands=[
                    "Capture memory dumps from affected systems",
                    "Collect relevant log files",
                    "Document all findings with timestamps",
                    "Create disk images if necessary"
                ],
                expected_outcome="Evidence securely collected and preserved",
                approval_required=False
            ),
            PlaybookStep(
                step_number=3,
                title="Containment - Isolate Affected Systems",
                description="Contain the incident to prevent further spread while maintaining business operations where possible.",
                action_type="contain",
                commands=[
                    "Isolate affected systems from the network",
                    "Disable compromised user accounts",
                    "Block malicious IP addresses at firewall",
                    "Update IDS/IPS signatures"
                ],
                expected_outcome="Incident contained, no further spread",
                approval_required=require_approval
            ),
            PlaybookStep(
                step_number=4,
                title="Threat Eradication",
                description="Remove the threat from the environment completely.",
                action_type="eradicate",
                commands=[
                    "Remove malware from affected systems",
                    "Close unauthorized access points",
                    "Patch vulnerabilities that were exploited",
                    "Reset compromised credentials"
                ],
                expected_outcome="All traces of the threat removed",
                approval_required=require_approval
            ),
            PlaybookStep(
                step_number=5,
                title="System Recovery and Validation",
                description="Restore affected systems to normal operation and validate security.",
                action_type="recover",
                commands=[
                    "Restore systems from clean backups if needed",
                    "Apply all security updates and patches",
                    "Reconfigure security controls",
                    "Monitor for signs of persistence"
                ],
                expected_outcome="Systems restored and operating securely",
                approval_required=require_approval
            ),
            PlaybookStep(
                step_number=6,
                title="Post-Incident Analysis",
                description="Conduct a thorough review of the incident and update defenses.",
                action_type="investigate",
                commands=[
                    "Document lessons learned",
                    "Update detection rules based on IOCs",
                    "Review and update security policies",
                    "Conduct team debrief"
                ],
                expected_outcome="Documentation complete, defenses improved",
                approval_required=False
            )
        ]
        
        return steps
