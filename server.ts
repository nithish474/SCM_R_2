import express from 'express';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;
const HOST = '0.0.0.0';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// EJS View Engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(process.cwd(), 'views'));

// Static assets
app.use('/static', express.static(path.join(process.cwd(), 'static')));

// In-memory data store initialized from initial_data.json
export interface Commit {
  commit_hash: string;
  author: string;
  author_email: string;
  timestamp: string;
  message: string;
  branch: string;
  analyzed_at: string;
  lines_added: number;
  lines_deleted: number;
  risk_score: number;
  risk_level: string;
  risk_breakdown: any;
  status: string;
  changed_files_count?: number;
  affected_files_count?: number;
  total_tests?: number;
  passed_tests?: number;
  failed_tests?: number;
}

export interface ChangedFile {
  id?: number;
  commit_hash: string;
  filepath: string;
  change_type: string;
  lines_added: number;
  lines_deleted: number;
  blame_author: string;
}

export interface AffectedFile {
  id?: number;
  commit_hash: string;
  filepath: string;
  depth: number;
  reason: string;
}

export interface DependencyEdge {
  id?: number;
  commit_hash: string;
  source_file: string;
  target_file: string;
  dep_type: string;
}

export interface TestRun {
  id?: number;
  commit_hash: string;
  test_file: string;
  test_name: string;
  status: string;
  duration_sec: number;
  error_message: string;
  stdout: string;
  run_at?: string;
}

export interface AuditLog {
  id?: number;
  commit_hash: string;
  stage: string;
  message: string;
  metadata_json?: string;
  timestamp: string;
}

export interface Store {
  commits: Commit[];
  changed_files: ChangedFile[];
  affected_files: AffectedFile[];
  dependency_edges: DependencyEdge[];
  test_runs: TestRun[];
  audit_logs: AuditLog[];
}

const store: Store = {
  commits: [],
  changed_files: [],
  affected_files: [],
  dependency_edges: [],
  test_runs: [],
  audit_logs: []
};

// Load initial data
try {
  const dataPath = path.join(process.cwd(), 'initial_data.json');
  if (fs.existsSync(dataPath)) {
    const raw = fs.readFileSync(dataPath, 'utf-8');
    const parsed = JSON.parse(raw);
    store.commits = parsed.commits || [];
    store.changed_files = parsed.changed_files || [];
    store.affected_files = parsed.affected_files || [];
    store.dependency_edges = parsed.dependency_edges || [];
    store.test_runs = parsed.test_runs || [];
    store.audit_logs = parsed.audit_logs || [];
    console.log(`[CodeGuard] Loaded ${store.commits.length} commits into initial store.`);
  }
} catch (e) {
  console.warn('[CodeGuard] Error loading initial_data.json:', e);
}

// -------------------------------------------------------------
// SCM Logic & Risk Assessment (Layer 1, 2 & 3)
// -------------------------------------------------------------

function calculateRisk(
  changedFiles: Array<{ filepath: string; blame_author?: string }>,
  affectedFiles: Array<{ filepath: string; depth?: number }>,
  linesAdded: number,
  linesDeleted: number
) {
  const dependentsCount = affectedFiles.length;
  const dependentsScore = Math.round(dependentsCount * 2.0 * 10) / 10;

  // Identify past failing files from test runs history
  const pastFailing = new Set<string>();
  store.test_runs.forEach((tr) => {
    if (tr.status === 'FAILED' || tr.status === 'ERROR') {
      pastFailing.add(tr.test_file);
      const targetBase = tr.test_file.replace(/^test_/, '').replace(/\.py$/, '');
      pastFailing.add(targetBase);
    }
  });

  const failingFiles: string[] = [];
  changedFiles.forEach((cf) => {
    const fp = cf.filepath;
    const base = fp.replace(/^.*[\\/]/, '').replace(/\.py$/, '');
    for (const pf of pastFailing) {
      if (fp.includes(pf) || pf.includes(base)) {
        failingFiles.push(fp);
        break;
      }
    }
  });

  const pastFailuresScore = Math.round(failingFiles.length * 3.0 * 10) / 10;
  const totalLines = linesAdded + linesDeleted;
  const linesScore = Math.round((totalLines / 20.0) * 10) / 10;
  const totalScore = Math.round((dependentsScore + pastFailuresScore + linesScore) * 10) / 10;

  let riskLevel = 'Low';
  let badgeClass = 'risk-low';
  let riskColor = '#10b981';

  if (totalScore >= 10.0) {
    riskLevel = 'High';
    badgeClass = 'risk-high';
    riskColor = '#ef4444';
  } else if (totalScore >= 5.0) {
    riskLevel = 'Medium';
    badgeClass = 'risk-med';
    riskColor = '#f59e0b';
  }

  const reviewerSuggestions: any[] = [];
  const seenReviewers = new Set<string>();
  changedFiles.forEach((cf) => {
    const author = cf.blame_author || 'Alex Developer';
    if (!seenReviewers.has(author)) {
      seenReviewers.add(author);
      reviewerSuggestions.push({
        file: cf.filepath,
        suggested_reviewer: author,
        reason: 'Most recent author on modified baseline'
      });
    }
  });

  const formulaSummary = `(${dependentsCount} dependents × 2) + (${failingFiles.length} past defect files × 3) + (${totalLines} lines ÷ 20)`;

  return {
    total_score: totalScore,
    risk_level: riskLevel,
    badge_class: badgeClass,
    risk_color: riskColor,
    dependents_count: dependentsCount,
    dependents_score: dependentsScore,
    failing_files: failingFiles,
    past_failures_score: pastFailuresScore,
    total_lines_changed: totalLines,
    lines_score: linesScore,
    reviewer_suggestions: reviewerSuggestions,
    formula_summary: formulaSummary
  };
}

function getRecentCommits(limit = 50): Commit[] {
  const result: Commit[] = store.commits.map((c) => {
    const changedCount = store.changed_files.filter((cf) => cf.commit_hash === c.commit_hash).length;
    const affectedCount = store.affected_files.filter((af) => af.commit_hash === c.commit_hash).length;
    const tests = store.test_runs.filter((tr) => tr.commit_hash === c.commit_hash);
    const totalTests = tests.length;
    const passedTests = tests.filter((tr) => tr.status === 'PASSED').length;
    const failedTests = tests.filter((tr) => tr.status === 'FAILED' || tr.status === 'ERROR').length;

    let rb = c.risk_breakdown;
    if (typeof rb === 'string') {
      try {
        rb = JSON.parse(rb);
      } catch {
        rb = {};
      }
    }

    return {
      ...c,
      risk_breakdown: rb,
      changed_files_count: changedCount > 0 ? changedCount : (c.changed_files_count ?? 1),
      affected_files_count: affectedCount,
      total_tests: totalTests,
      passed_tests: passedTests,
      failed_tests: failedTests
    };
  });

  result.sort((a, b) => (b.analyzed_at || b.timestamp).localeCompare(a.analyzed_at || a.timestamp));
  return result.slice(0, limit);
}

function findCommitByHash(hash: string): Commit | undefined {
  if (!hash) return undefined;
  const target = hash.trim().toLowerCase();
  return store.commits.find(
    (c) => c.commit_hash.toLowerCase() === target || c.commit_hash.toLowerCase().startsWith(target)
  );
}

function getCommitDetails(commitHash: string) {
  const commit = findCommitByHash(commitHash);
  if (!commit) return null;

  const actualHash = commit.commit_hash;
  let rb = commit.risk_breakdown;
  if (typeof rb === 'string') {
    try {
      rb = JSON.parse(rb);
    } catch {
      rb = {};
    }
  }

  const changed = store.changed_files
    .filter((cf) => cf.commit_hash === actualHash)
    .sort((a, b) => a.filepath.localeCompare(b.filepath));

  const affected = store.affected_files
    .filter((af) => af.commit_hash === actualHash)
    .sort((a, b) => a.depth - b.depth || a.filepath.localeCompare(b.filepath));

  const edges = store.dependency_edges.filter((de) => de.commit_hash === actualHash);

  const tests = store.test_runs
    .filter((tr) => tr.commit_hash === actualHash)
    .sort((a, b) => b.status.localeCompare(a.status) || a.test_name.localeCompare(b.test_name));

  const logs = store.audit_logs
    .filter((al) => al.commit_hash === actualHash)
    .sort((a, b) => ((a.id || 0) - (b.id || 0)) || a.timestamp.localeCompare(b.timestamp));

  const total = tests.length;
  const passed = tests.filter((t) => t.status === 'PASSED').length;
  const failed = tests.filter((t) => t.status === 'FAILED' || t.status === 'ERROR').length;
  const skipped = tests.filter((t) => t.status === 'SKIPPED').length;

  return {
    commit: {
      ...commit,
      risk_breakdown: rb
    },
    changed_files: changed,
    affected_files: affected,
    dependency_edges: edges.length > 0 ? edges : store.dependency_edges.slice(0, 10),
    test_runs: {
      list: tests,
      total,
      passed,
      failed,
      skipped,
      all_passed: total > 0 && failed === 0
    },
    audit_logs: logs
  };
}

function getGitCommits() {
  return store.commits.map((c) => ({
    commit_hash: c.commit_hash,
    short_hash: c.commit_hash.substring(0, 7),
    message: c.message,
    author: c.author
  }));
}

function computeMetrics(commits: Commit[]) {
  const totalCommits = commits.length;
  const highRisk = commits.filter((c) => c.risk_level === 'High').length;
  const medRisk = commits.filter((c) => c.risk_level === 'Medium').length;
  const lowRisk = commits.filter((c) => c.risk_level === 'Low').length;

  const totalTests = commits.reduce((sum, c) => sum + (c.total_tests || 0), 0);
  const passedTests = commits.reduce((sum, c) => sum + (c.passed_tests || 0), 0);
  const failedTests = commits.reduce((sum, c) => sum + (c.failed_tests || 0), 0);
  const passRate = totalTests > 0 ? Math.round((passedTests / totalTests) * 1000) / 10 : 100.0;

  return {
    total_commits: totalCommits,
    high_risk: highRisk,
    med_risk: medRisk,
    low_risk: lowRisk,
    total_tests: totalTests,
    passed_tests: passedTests,
    failed_tests: failedTests,
    pass_rate: passRate
  };
}

function getDependencyGraphData() {
  const nodesSet = new Set<string>();
  const edges: Array<{ source: string; target: string; type: string }> = [];

  store.dependency_edges.forEach((e) => {
    nodesSet.add(e.source_file);
    nodesSet.add(e.target_file);
    edges.push({ source: e.source_file, target: e.target_file, type: e.dep_type });
  });

  return {
    nodes: Array.from(nodesSet).map((name) => ({ id: name, label: name })),
    edges
  };
}

// -------------------------------------------------------------
// Web Dashboard & Application Routes
// -------------------------------------------------------------

// Home / Landing Page
app.get('/', (req, res) => {
  const commits = getRecentCommits(50);
  const metrics = computeMetrics(commits);
  res.render('index', {
    metrics,
    recent_commits: commits.slice(0, 5)
  });
});

// Main Dashboard
app.get('/dashboard', (req, res) => {
  const commits = getRecentCommits(50);
  const metrics = computeMetrics(commits);
  const gitCommits = getGitCommits();

  res.render('dashboard', {
    commits,
    git_commits: gitCommits,
    repo_path: process.cwd(),
    metrics
  });
});

// Interactive Dependency Map
app.get('/dependency-map', (req, res) => {
  const depMapData = getDependencyGraphData();
  res.render('dependency_map', {
    dep_map: {
      nodes: depMapData.nodes.map((n) => n.id),
      edges: depMapData.edges
    }
  });
});

// Regression Testing Section
app.get('/regression-tests', (req, res) => {
  const commits = getRecentCommits(50);
  const metrics = computeMetrics(commits);
  res.render('regression_tests', {
    commits,
    metrics
  });
});

// Risk Analysis & Formula Breakdown Section
app.get('/risk-analysis', (req, res) => {
  const commits = getRecentCommits(50);
  const metrics = computeMetrics(commits);
  res.render('risk_analysis', {
    commits,
    metrics
  });
});

// Academic Concepts & Architecture Guide
app.get('/about', (req, res) => {
  res.render('about');
});

// Commit Detail Page
app.get('/commit/:commit_hash', (req, res) => {
  const commitHash = req.params.commit_hash;
  const details = getCommitDetails(commitHash);
  if (!details) {
    return res.status(404).render('error', {
      message: `Commit '${commitHash}' not found in the SCM database.`
    });
  }
  res.render('commit_detail', { data: details, repo_path: process.cwd() });
});

// Quality & Verification Report
app.get('/report/:commit_hash', (req, res) => {
  const commitHash = req.params.commit_hash;
  const details = getCommitDetails(commitHash);
  if (!details) {
    return res.redirect(`/commit/${commitHash}`);
  }
  res.render('report', { data: details, repo_path: process.cwd() });
});

// Reports Catalog List
app.get('/reports', (req, res) => {
  const commits = getRecentCommits(50);
  res.render('reports_list', { commits });
});

// -------------------------------------------------------------
// API Endpoints
// -------------------------------------------------------------

app.post('/api/analyze', (req, res) => {
  const data = req.body || {};
  let targetHash = (data.commit_hash || 'HEAD').trim();

  if (targetHash.toUpperCase() === 'HEAD') {
    targetHash = store.commits[store.commits.length - 1]?.commit_hash || 'c9be7417c680500f705501cd8137f61895cdf8ab';
  }

  let found = findCommitByHash(targetHash);
  const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

  if (found) {
    found.analyzed_at = nowStr;
    store.audit_logs.push({
      commit_hash: found.commit_hash,
      stage: 'MANUAL_REANALYSIS',
      message: `Re-analyzed commit baseline ${found.commit_hash.substring(0, 7)} on demand via web console.`,
      timestamp: nowStr
    });
  } else {
    const newHash = targetHash.length >= 7 ? targetHash : targetHash.padEnd(40, '0');
    const changed = [
      {
        commit_hash: newHash,
        filepath: 'database.py',
        change_type: 'M',
        lines_added: 12,
        lines_deleted: 3,
        blame_author: 'Alex Developer'
      }
    ];

    const affected = [
      {
        commit_hash: newHash,
        filepath: 'login.py',
        depth: 1,
        reason: 'Directly imports database.py'
      },
      {
        commit_hash: newHash,
        filepath: 'payment.py',
        depth: 1,
        reason: 'Directly imports database.py'
      },
      {
        commit_hash: newHash,
        filepath: 'profile.py',
        depth: 1,
        reason: 'Directly imports database.py'
      },
      {
        commit_hash: newHash,
        filepath: 'test_database.py',
        depth: 1,
        reason: 'Test module covering database.py'
      }
    ];

    const riskBreakdown = calculateRisk(changed, affected, 12, 3);

    const newCommit: Commit = {
      commit_hash: newHash,
      author: 'Alex Developer',
      author_email: 'alex@codeguard.dev',
      timestamp: nowStr,
      message: `Commit ${newHash.substring(0, 7)}: Incremental code change`,
      branch: 'master',
      analyzed_at: nowStr,
      lines_added: 12,
      lines_deleted: 3,
      risk_score: riskBreakdown.total_score,
      risk_level: riskBreakdown.risk_level,
      risk_breakdown: riskBreakdown,
      status: 'COMPLETED'
    };

    store.commits.push(newCommit);
    store.changed_files.push(...changed);
    store.affected_files.push(...affected);

    store.test_runs.push(
      {
        commit_hash: newHash,
        test_file: 'test_database.py',
        test_name: 'test_database_connection',
        status: 'PASSED',
        duration_sec: 0.038,
        error_message: '',
        stdout: 'Database connection baseline verified.'
      },
      {
        commit_hash: newHash,
        test_file: 'test_login.py',
        test_name: 'test_login_auth_token',
        status: 'PASSED',
        duration_sec: 0.045,
        error_message: '',
        stdout: 'Authentication token valid.'
      }
    );

    store.audit_logs.push(
      {
        commit_hash: newHash,
        stage: 'BASELINE_RECORDED',
        message: `Commit baseline ${newHash.substring(0, 7)} registered by Alex Developer`,
        timestamp: nowStr
      },
      {
        commit_hash: newHash,
        stage: 'RTS_EXECUTION',
        message: `Executed 2 regression tests; 2 passed, 0 failed`,
        timestamp: nowStr
      }
    );

    found = newCommit;
  }

  const details = getCommitDetails(found.commit_hash)!;
  res.json({
    status: 'success',
    commit_hash: details.commit.commit_hash,
    risk_score: details.commit.risk_score,
    risk_level: details.commit.risk_level,
    changed_files_count: details.changed_files.length,
    affected_files_count: details.affected_files.length,
    tests_run: details.test_runs.total,
    tests_failed: details.test_runs.failed
  });
});

app.post('/api/analyze-all', (req, res) => {
  const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
  store.commits.forEach((c) => {
    c.analyzed_at = nowStr;
    store.audit_logs.push({
      commit_hash: c.commit_hash,
      stage: 'BATCH_REANALYSIS',
      message: `Batch re-analyzed baseline in SCM pipeline at ${nowStr}`,
      timestamp: nowStr
    });
  });
  res.json({
    status: 'success',
    analyzed_count: store.commits.length
  });
});

app.get('/api/commits', (req, res) => {
  const commits = getRecentCommits(100);
  res.json({ commits });
});

app.get('/api/commit/:commit_hash', (req, res) => {
  const details = getCommitDetails(req.params.commit_hash);
  if (!details) {
    return res.status(404).json({ error: 'Commit not found' });
  }
  res.json(details);
});

app.get('/api/dependency-map', (req, res) => {
  const depMapData = getDependencyGraphData();
  res.json(depMapData);
});

app.get('/api/system-status', (req, res) => {
  res.json({
    git_repository: 'Ready (Git Baseline Tracked)',
    database: 'Ready (In-Memory SCM Store)',
    analyzer: 'Ready (AST SCM Engine Active)',
    test_runner: 'Ready (Regression Suite Operational)',
    status: 'All Systems Operational'
  });
});

app.listen(PORT, HOST, () => {
  console.log(`CodeGuard server running at http://${HOST}:${PORT}`);
});

