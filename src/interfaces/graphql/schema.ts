/**
 * GraphQL schema (Bonus B). A superset of the brief's example:
 *   type Scan { id: ID!, status: String!, criticalVulnerabilities: [Vulnerability] }
 * `status` is an enum whose values are exactly the REST statuses, and the vulnerability list is paginated
 * (`first` is clamped server-side) so a single query can never pull an unbounded result into memory.
 */
export const schema = /* GraphQL */ `
  enum ScanStatus {
    Queued
    Scanning
    Finished
    Failed
  }

  enum ScanPhase {
    cloning
    scanning
    parsing
  }

  type Vulnerability {
    "CVE / GHSA identifier"
    id: ID!
    "Opaque cursor: pass as \`after\` to continue after this item"
    cursor: ID!
    pkgName: String!
    installedVersion: String
    fixedVersion: String
    severity: String!
    title: String
    description: String
    primaryUrl: String
    target: String!
    pkgType: String
    cvssScore: Float
    publishedDate: String
  }

  type ScanError {
    code: String!
    message: String!
  }

  type ScanStats {
    "Float because report sizes can exceed GraphQL's 32-bit Int"
    reportBytes: Float!
    vulnerabilitiesScanned: Int!
    malformedSkipped: Int!
    durationMs: Int!
    peakRssMb: Int!
  }

  type Scan {
    id: ID!
    status: ScanStatus!
    repoUrl: String!
    phase: ScanPhase
    progressPct: Int
    attempt: Int!
    criticalCount: Int
    "Null until status is Finished. Paginated: \`first\` is clamped to 1..1000."
    criticalVulnerabilities(first: Int = 100, after: ID): [Vulnerability!]
    stats: ScanStats
    error: ScanError
    createdAt: String!
    startedAt: String
    finishedAt: String
  }

  type Query {
    scan(id: ID!): Scan
  }

  type Mutation {
    "Queue a scan. Returns immediately with status Queued (or the already-active scan for the same repository)."
    startScan(repoUrl: String!): Scan!
  }
`;
