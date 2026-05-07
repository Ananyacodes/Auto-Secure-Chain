import React from 'react';
import './App.css';

type Mitigation = {
    id: string;
    title: string;
    description: string;
};

type SignatureInfo = {
    sig_found: boolean;
    pubkey_found: boolean;
    valid: boolean | null;
    error?: string | null;
};

type ScanFile = {
    file: string;
    size_bytes: number;
    sha256: string;
    entropy: number;
    strings_count: number;
    matches: Array<{ rule: string; tags: string[] }>;
    suspicious_strings: string[];
    signature: SignatureInfo;
    severity_score: number;
    recommended_mitigations: Mitigation[];
};

type ScanReport = {
    scanned_at: string | null;
    files: ScanFile[];
};

const sampleReport: ScanReport = {
    scanned_at: '2025-11-29T18:50:53.488144Z',
    files: [
        {
            file: 'sample.bin',
            size_bytes: 187,
            sha256: '44117ae3837633821420b3d891a190ad1fa3dcbff7158a9d56432114386a4685',
            entropy: 4.805447551372179,
            strings_count: 8,
            matches: [],
            suspicious_strings: [
                'JAGUAR_PROVISION=1',
                'PROVISION_TOKEN=DEMO-ABCDEFG-12345',
                'root:toor',
                'telnetd',
                'DEBUG_MODE=1',
                '-----BEGIN RSA PRIVATE KEY-----',
                '-----END RSA PRIVATE KEY-----',
            ],
            signature: {
                sig_found: true,
                pubkey_found: false,
                valid: null,
                error: null,
            },
            severity_score: 3,
            recommended_mitigations: [
                {
                    id: 'require_fw_signing',
                    title: 'Enforce signed firmware with verified public keys',
                    description:
                        'Ensure each device verifies firmware signatures with a vetted public key and rejects unsigned or invalid updates.',
                },
                {
                    id: 'disable_telnet',
                    title: 'Disable telnet',
                    description: 'Remove telnet and other cleartext shells.',
                },
                {
                    id: 'protect_debug',
                    title: 'Protect debug interfaces',
                    description: 'Disable or gate JTAG/UART in production and require stronger attestation.',
                },
                {
                    id: 'rotate_tokens',
                    title: 'Rotate hardcoded tokens',
                    description: 'Remove hardcoded provisioning tokens and issue unique per-device credentials.',
                },
            ],
        },
    ],
};

function formatDate(value: string | null): string {
    if (!value) {
        return 'No report loaded';
    }

    try {
        return new Intl.DateTimeFormat(undefined, {
            dateStyle: 'medium',
            timeStyle: 'short',
        }).format(new Date(value));
    } catch {
        return value;
    }
}

function clampScore(score: number): number {
    return Math.max(0, Math.min(100, Math.round(score * 12)));
}

const App: React.FC = () => {
    const [report, setReport] = React.useState<ScanReport>(sampleReport);
    const [selectedFile, setSelectedFile] = React.useState<string>(sampleReport.files[0]?.file ?? '');
    const [status, setStatus] = React.useState('Showing sample report. Upload a report.json to replace it.');
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState<{ message: string; type: 'error' | 'success' } | null>(null);

    const selected = report.files.find((file) => file.file === selectedFile) ?? report.files[0];

    const showError = (message: string, type: 'error' | 'success' = 'error') => {
        setError({ message, type });
        setTimeout(() => setError(null), 5000); // Auto-dismiss after 5 seconds
    };

    React.useEffect(() => {
        const loadReport = async () => {
            setIsLoading(true);
            try {
                // Try to fetch from Flask backend first
                const apiResponse = await fetch('http://localhost:5000/api/report');
                if (apiResponse.ok) {
                    const data: ScanReport = await apiResponse.json();
                    if (data?.files?.length) {
                        setReport(data);
                        setSelectedFile(data.files[0].file);
                        setStatus('Loaded report from Flask backend.');
                        showError('Successfully loaded report from backend!', 'success');
                        return;
                    }
                }

                // Fallback: try to load from local report.json in public folder
                const localResponse = await fetch('/report.json');
                if (localResponse.ok) {
                    const data: ScanReport = await localResponse.json();
                    if (data?.files?.length) {
                        setReport(data);
                        setSelectedFile(data.files[0].file);
                        setStatus('Loaded report.json from the app public folder.');
                        return;
                    }
                }

                // No data available, keep sample
                setStatus('Showing sample report. No backend or local report found. Start Flask backend: python AutoSecureChain/ui/app.py');
            } catch (err) {
                console.error('Failed to load report:', err);
                setStatus('Showing sample report. Failed to load external reports.');
                showError('Failed to connect to backend. Using sample data.');
            } finally {
                setIsLoading(false);
            }
        };

        loadReport();
    }, []);

    const totals = React.useMemo(() => {
        const files = report.files;
        const critical = files.filter((file) => file.severity_score >= 7).length;
        const warned = files.filter((file) => file.severity_score >= 3 && file.severity_score < 7).length;
        const clean = files.length - critical - warned;

        return {
            files: files.length,
            critical,
            warned,
            clean,
        };
    }, [report.files]);

    function handleUpload(event: React.ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        if (!file) {
            return;
        }

        setIsLoading(true);
        const reader = new FileReader();
        reader.onload = () => {
            try {
                const parsed = JSON.parse(String(reader.result)) as ScanReport;
                if (!parsed?.files?.length) {
                    throw new Error('The uploaded file does not look like a scan report.');
                }

                setReport(parsed);
                setSelectedFile(parsed.files[0].file);
                setStatus(`Loaded ${file.name}.`);
                showError(`Successfully loaded ${file.name}!`, 'success');
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Failed to read the uploaded file.';
                setStatus(errorMessage);
                showError(errorMessage);
            } finally {
                setIsLoading(false);
            }
        };

        reader.onerror = () => {
            setStatus('Failed to read the uploaded file.');
            showError('Failed to read the uploaded file.');
            setIsLoading(false);
        };

        reader.readAsText(file);
    }

    return (
        <div className="app-shell">
            <div className="app-background" />
            <main className="app-frame">
                <header className="hero">
                    <div>
                        <p className="eyebrow">AutoSecureChain</p>
                        <h1>Firmware scan dashboard</h1>
                        <p className="hero-copy">
                            Review static findings, signature status, and suggested mitigations from a generated report.
                        </p>
                    </div>
                    <div className="hero-actions">
                        <label className="upload-button">
                            Load report.json
                            <input type="file" accept="application/json" onChange={handleUpload} />
                        </label>
                        <div className="status-pill">
                            {isLoading && <span className="loading-spinner" aria-hidden="true" />} {status}
                        </div>
                    </div>
                </header>

                <section className="stats-grid">
                    <article className="stat-card accent">
                        <span className="stat-label">Files</span>
                        <strong>{totals.files}</strong>
                    </article>
                    <article className="stat-card warning">
                        <span className="stat-label">Warned</span>
                        <strong>{totals.warned}</strong>
                    </article>
                    <article className="stat-card danger">
                        <span className="stat-label">Critical</span>
                        <strong>{totals.critical}</strong>
                    </article>
                    <article className="stat-card success">
                        <span className="stat-label">Clean</span>
                        <strong>{totals.clean}</strong>
                    </article>
                </section>

                <section className="content-grid">
                    <aside className="panel file-list-panel">
                        <div className="panel-header">
                            <div>
                                <p className="panel-kicker">Scanned at</p>
                                <h2>{formatDate(report.scanned_at)}</h2>
                            </div>
                        </div>

                        <div className="file-list">
                            {report.files.map((file) => (
                                <button
                                    key={file.file}
                                    className={`file-row ${selected?.file === file.file ? 'active' : ''}`}
                                    onClick={() => setSelectedFile(file.file)}
                                    type="button"
                                >
                                    <span>
                                        <strong>{file.file}</strong>
                                        <small>{file.size_bytes} bytes</small>
                                    </span>
                                    <span className={`severity severity-${Math.min(3, Math.floor(file.severity_score / 3))}`}>
                                        {file.severity_score}
                                    </span>
                                </button>
                            ))}
                        </div>
                    </aside>

                    <section className="panel detail-panel">
                        {selected ? (
                            <>
                                <div className="panel-header detail-header">
                                    <div>
                                        <p className="panel-kicker">Selected file</p>
                                        <h2>{selected.file}</h2>
                                    </div>
                                    <div className="score-ring" aria-label={`Severity score ${selected.severity_score}`}>
                                        <span>{selected.severity_score}</span>
                                    </div>
                                </div>

                                <div className="detail-metrics">
                                    <article>
                                        <span>Entropy</span>
                                        <strong>{selected.entropy.toFixed(2)}</strong>
                                    </article>
                                    <article>
                                        <span>Strings</span>
                                        <strong>{selected.strings_count}</strong>
                                    </article>
                                    <article>
                                        <span>Size</span>
                                        <strong>{selected.size_bytes} bytes</strong>
                                    </article>
                                    <article>
                                        <span>Signature</span>
                                        <strong>{selected.signature.sig_found ? (selected.signature.valid ? 'Valid' : 'Needs review') : 'Missing'}</strong>
                                    </article>
                                </div>

                                <div className="detail-columns">
                                    <section>
                                        <h3>Findings</h3>
                                        <div className="chip-list">
                                            {selected.suspicious_strings.length ? (
                                                selected.suspicious_strings.map((item) => (
                                                    <span key={item} className="chip danger-chip">
                                                        {item}
                                                    </span>
                                                ))
                                            ) : (
                                                <span className="muted">No suspicious strings detected.</span>
                                            )}
                                        </div>
                                    </section>

                                    <section>
                                        <h3>Mitigations</h3>
                                        <div className="mitigation-list">
                                            {selected.recommended_mitigations.map((mitigation) => (
                                                <article key={mitigation.id} className="mitigation-card">
                                                    <strong>{mitigation.title}</strong>
                                                    <p>{mitigation.description}</p>
                                                </article>
                                            ))}
                                        </div>
                                    </section>
                                </div>

                                <section className="artifact-block">
                                    <div>
                                        <h3>Hashes and signature state</h3>
                                        <p className="muted">{selected.sha256}</p>
                                    </div>
                                    <div className="signature-grid">
                                        <span>Signature present: {selected.signature.sig_found ? 'Yes' : 'No'}</span>
                                        <span>Public key present: {selected.signature.pubkey_found ? 'Yes' : 'No'}</span>
                                        <span>Verification error: {selected.signature.error || 'None'}</span>
                                        <span>Progress score: {clampScore(selected.severity_score)}/100</span>
                                    </div>
                                </section>
                            </>
                        ) : (
                            <div className="empty-state">No files available in this report.</div>
                        )}
                    </section>
                </section>
            </main>

            {/* Loading overlay */}
            {isLoading && (
                <div className="loading-overlay">
                    <div className="loading-content">
                        <div className="loading-spinner" style={{ width: '32px', height: '32px', margin: '0 auto 16px' }} />
                        <h3>Loading report data...</h3>
                        <p>Please wait while we fetch the latest scan results.</p>
                    </div>
                </div>
            )}

            {/* Error toast */}
            {error && (
                <div className={`error-toast ${error.type}`}>
                    <h4>{error.type === 'success' ? 'Success' : 'Error'}</h4>
                    <p>{error.message}</p>
                </div>
            )}
        </div>
    );
};

export default App;