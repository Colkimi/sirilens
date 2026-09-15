export type SecurityIntent =
  | 'cveSearch'
  | 'help'
  | 'dependencyScan'
  | 'exploitedVulnerabilities'
  | 'recentVulnerabilities'
  | 'criticalAlerts'
  | 'threatAnalysis'
  | 'productVulnerability'
  | 'generalSearch';