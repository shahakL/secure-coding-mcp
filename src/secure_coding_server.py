from dataclasses import dataclass, field
from enum import StrEnum

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession


@dataclass
class SecureThoughtInput:
    """Input data for processing a secure thought.

    Args:
        thought: The security analysis text
        thought_number: Position in the thought sequence (starts at 1)
        total_thoughts: Estimated total thoughts needed (adjustable)
        next_thought_needed: Whether more security analysis is needed
        phase: Current security phase from ThoughtPhase enum
        security_aspects: List of security aspects being considered from SecurityAspect enum
        is_revision: Whether this revises a previous security consideration
        revises_thought: Number of the thought being revised, if any
        branch_from_thought: Thought number to branch from for alternative approaches
        branch_id: Identifier for the current analysis branch
    """

    thought: str
    thought_number: int
    total_thoughts: int
    next_thought_needed: bool
    phase: str
    security_aspects: list[str]
    is_revision: bool = False
    revises_thought: int | None = None
    branch_from_thought: int | None = None
    branch_id: str | None = None


@dataclass
class ThoughtResult:
    """Result of processing a secure coding thought.

    Args:
        thought_number: Position in the thought sequence (starts at 1)
        total_thoughts: Estimated total thoughts needed
        next_thought_needed: Whether more security analysis is needed
        thought_history_length: Number of thoughts processed so far
        current_phase: Name of the current security analysis phase
        security_aspects: List of security aspects being considered
        risk_level: Name of the assessed security risk level
        recommendations: List of security recommendations generated
        is_error: Whether an error occurred during processing
        error: Error message if is_error is True, None otherwise
    """

    thought_number: int
    total_thoughts: int
    next_thought_needed: bool
    thought_history_length: int
    current_phase: str
    security_aspects: list[str]
    risk_level: str | None
    recommendations: list[str] = field(default_factory=list)
    is_error: bool = False
    error: str | None = None


SECURE_CODING_TOOL_DESCRIPTION = """
        A tool for systematic security analysis and improvement of code through structured thinking.
        This tool guides AI agents through a comprehensive security review process, helping
        identify, assess, and mitigate security risks in code.

        When to use this tool:
        - Analyzing new code for potential security vulnerabilities
        - Reviewing existing code for security improvements
        - Designing secure system architectures
        - Planning security-focused refactoring
        - Implementing security features or controls
        - Verifying security measures and their effectiveness
        - Responding to security findings or incidents
        - Making security-critical design decisions

        Key features:
        - Structured progression through security analysis phases
        - Comprehensive coverage of security aspects
        - Automatic risk assessment and prioritization
        - Specific, actionable security recommendations
        - Support for revising thoughts based on new security insights
        - Ability to branch for exploring alternative security approaches
        - Progress tracking with security context

        Guidelines for AI agents:
        1. Start with THREAT_MODELING phase to identify potential risks
        2. Progress through phases systematically, but feel free to revise when new insights emerge
        3. For each thought, consider relevant security aspects from the SecurityAspect enum
        4. Generate specific, actionable security recommendations
        5. Use branching when exploring alternative security approaches
        6. Revise previous thoughts when security implications become clearer
        7. Always consider the security impact and risk level of each thought
        8. Provide concrete, implementable security guidance
        9. Verify security measures before completing the analysis
        10. Set next_thought_needed=False only when security analysis is complete

        Parameters:
            thought: Current security analysis, consideration, or recommendation
            thought_number: Position in the thought sequence (starts at 1)
            total_thoughts: Estimated total thoughts needed (adjustable)
            next_thought_needed: Whether more security analysis is needed
            phase: Current security phase (from ThoughtPhase enum)
            security_aspects: Security aspects being considered (from SecurityAspect enum)
            is_revision: Whether this revises a previous security consideration
            revises_thought: Number of the thought being revised
            branch_from_thought: Thought number to branch from for alternative approaches
            branch_id: Identifier for the current analysis branch
            ctx: Context for progress reporting and logging

        The tool ensures a methodical approach to security analysis by:
        1. Breaking down security concerns into manageable steps
        2. Maintaining context across the analysis process
        3. Adapting the analysis based on new security insights
        4. Generating practical security improvements
        5. Tracking progress and risk levels
        6. Providing clear security guidance

        Example thought progression:
        1. Identify potential security threats (THREAT_MODELING)
        2. Analyze specific vulnerabilities (VULNERABILITY_ASSESSMENT)
        3. Plan security controls (MITIGATION_PLANNING)
        4. Detail secure implementation (IMPLEMENTATION_GUIDANCE)
        5. Verify security measures (VERIFICATION)
        """


class SecurityAspect(StrEnum):
    """Enumeration of security aspects that can be considered in a thought."""

    INPUT_VALIDATION = "input_validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ENCRYPTION = "data_encryption"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    SESSION_MANAGEMENT = "session_management"
    DEPENDENCY_SECURITY = "dependency_security"
    CODE_INJECTION = "code_injection"
    DATA_EXPOSURE = "data_exposure"
    API_SECURITY = "api_security"
    SECURE_CONFIGURATION = "secure_configuration"
    SECRETS_MANAGEMENT = "secrets_management"
    ACCESS_CONTROL = "access_control"
    SECURE_COMMUNICATION = "secure_communication"


class SecurityRiskLevel(StrEnum):
    """Risk level assessment for security considerations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThoughtPhase(StrEnum):
    """Phases of security-focused code analysis."""

    THREAT_MODELING = "threat_modeling"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    MITIGATION_PLANNING = "mitigation_planning"
    IMPLEMENTATION_GUIDANCE = "implementation_guidance"
    VERIFICATION = "verification"


@dataclass
class SecureThought:
    """Represents a single security-focused thought in the analysis process."""

    thought: str
    thought_number: int
    total_thoughts: int
    next_thought_needed: bool
    phase: ThoughtPhase
    security_aspects: list[SecurityAspect]
    risk_level: SecurityRiskLevel | None = None
    recommendations: list[str] = field(default_factory=list)
    is_revision: bool = False
    revises_thought: int | None = None
    branch_from_thought: int | None = None
    branch_id: str | None = None

    def assess_security_impact(self) -> tuple[SecurityRiskLevel, list[str]]:
        """Analyze the security impact and generate recommendations."""
        recommendations: list[str] = []
        max_risk = SecurityRiskLevel.LOW

        for aspect in self.security_aspects:
            risk, rec = self._evaluate_aspect(aspect)
            if risk.value > max_risk.value:
                max_risk = risk
            recommendations.extend(rec)

        return max_risk, recommendations

    def _evaluate_aspect(self, aspect: SecurityAspect) -> tuple[SecurityRiskLevel, list[str]]:
        """Evaluate a specific security aspect and provide recommendations."""
        base_recs = {
            SecurityAspect.INPUT_VALIDATION: (
                SecurityRiskLevel.HIGH,
                [
                    "Implement strict input validation",
                    "Use parameterized queries",
                    "Sanitize all user input",
                ],
            ),
            SecurityAspect.AUTHENTICATION: (
                SecurityRiskLevel.CRITICAL,
                [
                    "Use secure password hashing",
                    "Implement MFA where possible",
                    "Enforce password policies",
                ],
            ),
            SecurityAspect.AUTHORIZATION: (
                SecurityRiskLevel.CRITICAL,
                [
                    "Implement role-based access control",
                    "Follow principle of least privilege",
                    "Verify authorization on all endpoints",
                ],
            ),
            # Add more aspect-specific evaluations here
        }

        return base_recs.get(
            aspect,
            (
                SecurityRiskLevel.MEDIUM,
                ["Review security implications", "Follow security best practices"],
            ),
        )


class SecureCodingServer:
    """MCP server for helping AI agents write more secure code."""

    def __init__(self) -> None:
        self.thought_history: list[SecureThought] = []
        self.branches: dict[str, list[SecureThought]] = {}
        self.disable_thought_logging = False

    def process_thought(self, input_data: SecureThoughtInput) -> ThoughtResult:
        """Process a new security-focused thought."""
        try:
            # Create and validate thought with proper security context
            thought = SecureThought(
                thought=input_data.thought,
                thought_number=input_data.thought_number,
                total_thoughts=input_data.total_thoughts,
                next_thought_needed=input_data.next_thought_needed,
                phase=ThoughtPhase[input_data.phase],
                security_aspects=[SecurityAspect[aspect] for aspect in input_data.security_aspects],
                is_revision=input_data.is_revision,
                revises_thought=input_data.revises_thought,
                branch_from_thought=input_data.branch_from_thought,
                branch_id=input_data.branch_id,
            )

            # Assess security implications
            risk_level, recommendations = thought.assess_security_impact()
            thought.risk_level = risk_level
            thought.recommendations = recommendations

            # Handle branching if needed
            if thought.branch_id and thought.branch_from_thought:
                if thought.branch_id not in self.branches:
                    self.branches[thought.branch_id] = []
                self.branches[thought.branch_id].append(thought)
            else:
                self.thought_history.append(thought)

            # Log security-focused thought
            if not self.disable_thought_logging:
                self._log_security_thought(thought)

            return ThoughtResult(
                thought_number=thought.thought_number,
                total_thoughts=thought.total_thoughts,
                next_thought_needed=thought.next_thought_needed,
                thought_history_length=len(self.thought_history),
                current_phase=thought.phase.name,
                security_aspects=[aspect.name for aspect in thought.security_aspects],
                risk_level=thought.risk_level.name if thought.risk_level else None,
                recommendations=thought.recommendations,
                is_error=False,
                error=None,
            )

        except Exception as e:
            return ThoughtResult(
                thought_number=0,
                total_thoughts=0,
                next_thought_needed=False,
                thought_history_length=len(self.thought_history),
                current_phase=ThoughtPhase.THREAT_MODELING.name,
                security_aspects=[],
                risk_level=None,
                recommendations=[],
                is_error=True,
                error=str(e),
            )

    def _log_security_thought(self, thought: SecureThought) -> None:
        """Log a security-focused thought with relevant context."""
        prefix = "[REVISION]" if thought.is_revision else "[THOUGHT]"
        phase_labels = {
            ThoughtPhase.THREAT_MODELING: "[THREAT]",
            ThoughtPhase.VULNERABILITY_ASSESSMENT: "[VULN]",
            ThoughtPhase.MITIGATION_PLANNING: "[MITIGATE]",
            ThoughtPhase.IMPLEMENTATION_GUIDANCE: "[IMPL]",
            ThoughtPhase.VERIFICATION: "[VERIFY]",
        }

        print(f"\n{prefix} {thought.thought_number}/{thought.total_thoughts}")
        print(f"{phase_labels[thought.phase]} Phase: {thought.phase.name}")
        print(f"Thought: {thought.thought}")
        print(f"Security Aspects: {', '.join(aspect.name for aspect in thought.security_aspects)}")

        if thought.risk_level:
            risk_labels = {
                SecurityRiskLevel.LOW: "[LOW]",
                SecurityRiskLevel.MEDIUM: "[MED]",
                SecurityRiskLevel.HIGH: "[HIGH]",
                SecurityRiskLevel.CRITICAL: "[CRIT]",
            }
            print(f"{risk_labels[thought.risk_level]} Risk Level: {thought.risk_level.name}")

        if thought.recommendations:
            print("Recommendations:")
            for rec in thought.recommendations:
                print(f"  * {rec}")


server = SecureCodingServer()
mcp = FastMCP("SecureCodingMCP")


@mcp.tool(name="securethinking", description=SECURE_CODING_TOOL_DESCRIPTION)
async def secure_coding_analysis(
    thought: str,
    thought_number: int,
    total_thoughts: int,
    next_thought_needed: bool,
    phase: str,
    security_aspects: list[str],
    is_revision: bool = False,
    revises_thought: int | None = None,
    branch_from_thought: int | None = None,
    branch_id: str | None = None,
    ctx: Context[ServerSession, None] | None = None,
) -> ThoughtResult:
    """Process a security-focused thought and provide recommendations."""
    # Process the security-focused thought
    result = server.process_thought(
        SecureThoughtInput(
            thought=thought,
            thought_number=thought_number,
            total_thoughts=total_thoughts,
            next_thought_needed=next_thought_needed,
            phase=phase,
            security_aspects=security_aspects,
            is_revision=is_revision,
            revises_thought=revises_thought,
            branch_from_thought=branch_from_thought,
            branch_id=branch_id,
        )
    )

    # Log progress with security context if available
    if ctx:
        progress = thought_number / total_thoughts
        phase_msg = f"Phase: {phase}"
        aspects_msg = f"Aspects: {', '.join(security_aspects)}"

        await ctx.report_progress(
            progress=progress,
            total=1.0,
            message=f"Processing thought {thought_number}/{total_thoughts} | {phase_msg} | {aspects_msg}",
        )

        # Log security recommendations if any
        if result.recommendations:
            await ctx.info("Security Recommendations:")
            for rec in result.recommendations:
                await ctx.info(f"• {rec}")

        # Log risk level if present
        if result.risk_level:
            risk_label = {"LOW": "[LOW]", "MEDIUM": "[MED]", "HIGH": "[HIGH]", "CRITICAL": "[CRIT]"}
            await ctx.warning(
                f"{risk_label.get(result.risk_level, '[WARN]')} Risk Level: {result.risk_level}"
            )

    return result
