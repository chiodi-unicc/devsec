import type { Severity } from "../domain/finding.js";

/**
 * Fixed, documented mapping from tool severities to devsec severities.
 * The original value is always kept in Finding.toolSeverity.
 *   semgrep: ERROR→high, WARNING→medium, INFO→low (newer CRITICAL/HIGH/MEDIUM/LOW map 1:1)
 *   trivy:   CRITICAL/HIGH/MEDIUM/LOW map 1:1, UNKNOWN→info
 */
const table: Readonly<Record<string, Severity>> = {
  CRITICAL: "critical",
  HIGH: "high",
  ERROR: "high",
  MEDIUM: "medium",
  WARNING: "medium",
  LOW: "low",
  INFO: "low",
  UNKNOWN: "info",
};

export const mapSeverity = (toolSeverity: string): Severity => table[toolSeverity.toUpperCase()] ?? "info";
