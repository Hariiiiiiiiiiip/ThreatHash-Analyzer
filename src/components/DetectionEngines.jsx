export default function DetectionEngines({ results }) {
  return (
    <div className="engines-grid">
      {results.map((engine, idx) => (
        <div key={idx} className={`engine-card ${engine.isMalicious ? 'malicious' : 'safe'}`}>
          <div className="engine-name">{engine.name}</div>
          <div className="engine-result">{engine.result}</div>
        </div>
      ))}
    </div>
  );
}
