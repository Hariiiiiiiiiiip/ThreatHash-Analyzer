import { useState } from 'react';
import FileUpload from './components/FileUpload';
import Scanner from './components/Scanner';
import ThreatReport from './components/ThreatReport';

function App() {
  const [appState, setAppState] = useState('upload'); // 'upload', 'scanning', 'results'
  const [selectedFile, setSelectedFile] = useState(null);
  const [report, setReport] = useState(null);

  const handleFileSelect = (file) => {
    setSelectedFile(file);
    setAppState('scanning');
  };

  const handleScanComplete = (scanReport) => {
    setReport(scanReport);
    setAppState('results');
  };

  const handleReset = () => {
    setSelectedFile(null);
    setReport(null);
    setAppState('upload');
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>ThreatHash Analyzer</h1>
        <p>Advanced File Integrity & Threat Intelligence Scanner</p>
      </header>

      <main>
        {appState === 'upload' && (
          <FileUpload onFileSelect={handleFileSelect} />
        )}
        
        {appState === 'scanning' && (
          <Scanner file={selectedFile} onComplete={handleScanComplete} />
        )}
        
        {appState === 'results' && report && (
          <ThreatReport report={report} onReset={handleReset} />
        )}
      </main>
    </div>
  );
}

export default App;
