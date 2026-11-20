"""The severity rubric, shared word for word by the Supervisor, Report Writer and Critic,
so all three judge severity against the same definitions.

(No curly braces anywhere: this text is pasted into ADK instructions, where {word}
would be read as a session-state placeholder.)
"""

SEVERITY_RUBRIC = """Severity rubric (pick the lowest level that fits the evidence):
- critical: active compromise with serious impact, such as credential theft (LSASS dumping),
  ransomware precursors (shadow copies deleted, logs cleared), data exfiltration, or several
  strong signals together with a past true-positive match for the same indicators.
- high: strong malicious signals that likely need containment, such as command-and-control
  beaconing, process injection, a LOLBin running code from a user-writable folder, or an Office
  document launching hidden or encoded PowerShell.
- medium: suspicious activity where a plausible benign explanation remains; needs investigation.
- low: only weak signals (for example an unsigned file or dynamic API resolution on its own).
- informational: benign or authorized activity, for example a match with a past false_positive or
  benign_true_positive and no strong new evidence."""
