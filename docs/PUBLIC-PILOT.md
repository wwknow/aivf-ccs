# Public Pilot Status

A public pilot deployment of this reconstructed stack has demonstrated the complete path:

```text
Safe action
  -> CCS ALLOW
  -> simulated tool path executes
  -> signed receipt
  -> signature VALID

Attack simulation
  -> shell_exec intent containing `curl ... | bash`
  -> RCE rule detects the pattern
  -> CCS DENY
  -> tool execution FALSE
  -> signed DENY receipt
  -> signature VALID
```

The public portal has also demonstrated receipt tamper detection for verdict, sequence, and block-reason changes, and rate limiting at the public edge.

Live demonstration used during the pilot: https://aivf.wwknow.com/

The public pilot is evidence of a working implementation, not a claim of formal certification or independent security audit.
