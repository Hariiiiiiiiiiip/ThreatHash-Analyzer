import DetectionEngines from './DetectionEngines';

export default function ThreatReport({ report, onReset }) {
  const {
    fileName,
    fileSize,
    sha256,
    detectionRatio,
    riskScore,
    severity,
    malwareFamily,
    threatLabels,
    firstSeen,
    scanStatus,
    engineResults
  } = report;

  return (
    <div className="glass-panel" style={{ padding: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', margin: 0 }}>Scan Results</h2>
        <button className="btn" onClick={onReset}>Scan Another File</button>
      </div>
      
      <div className="report-grid">
        <div className="report-section">
          <h2>File Information</h2>
          <div className="info-row">
            <span className="info-label">File Name</span>
            <span className="info-value">{fileName}</span>
          </div>
          <div className="info-row">
            <span className="info-label">File Size</span>
            <span className="info-value">{fileSize}</span>
          </div>
          <div className="info-row" style={{ flexDirection: 'column', gap: '0.5rem', alignItems: 'flex-start' }}>
            <span className="info-label">SHA-256</span>
            <span className="info-value mono" style={{ maxWidth: '100%' }}>{sha256}</span>
          </div>
          <div className="info-row">
            <span className="info-label">First Seen</span>
            <span className="info-value">{firstSeen}</span>
          </div>
        </div>

        <div className="report-section">
          <h2>Threat Analysis</h2>
          <div className="info-row">
            <span className="info-label">Detection Ratio</span>
            <span className="info-value" style={{ fontWeight: 'bold' }}>{detectionRatio}</span>
          </div>
          <div className="info-row">
            <span className="info-label">Risk Score</span>
            <span className="info-value">
              <span className={`badge ${severity}`}>{riskScore}</span>
            </span>
          </div>
          <div className="info-row">
            <span className="info-label">Scan Status</span>
            <span className="info-value">
               <span style={{ color: severity === 'safe' ? 'var(--safe-color)' : severity === 'malware' ? 'var(--malware-color)' : 'var(--suspicious-color)', fontWeight: 'bold' }}>
                 {scanStatus}
               </span>
            </span>
          </div>
          <div className="info-row">
            <span className="info-label">Malware Family</span>
            <span className="info-value">{malwareFamily}</span>
          </div>
          <div className="info-row">
            <span className="info-label">Threat Labels</span>
            <span className="info-value">{threatLabels}</span>
          </div>
        </div>
      </div>

      <div className="report-section" style={{ marginTop: '2rem' }}>
        <h2>Detection Engines</h2>
        <DetectionEngines results={engineResults} />
      </div>
    </div>
  );
}
