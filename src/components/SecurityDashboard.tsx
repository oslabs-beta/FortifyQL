import React, { useState } from 'react';
// import ScanConfigForm from './ScanConfigForm';
import ScanResultsTable from './ScanResultsTable';
import testData from './scanTestData.json';
import { ITestResult } from '../interfaces/results';

const SecurityDashboard: React.FC = () => {
  const [scanResults, setScanResults] = useState<ITestResult[]>(testData);
  const [loading, setLoading] = useState(false);

  const handleScanSubmit = async (
    endpoint: string,
    selectedTests: string[],
  ) => {
    setLoading(true);

    try {
      const response = await fetch(
        `YOUR_MIDDLEWARE_ENDPOINT?endpoint=${endpoint}&tests=${selectedTests.join(
          ',',
        )}`,
      );

      if (!response.ok) {
        throw new Error('');
      }

      const data = await response.json();
      setScanResults(data); // Update scanResults with the received data
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className='dashboard-container'>
      <h2 className='dashboard-title'>Security Dashboard</h2>
      {/* <ScanConfigForm onSubmit={handleScanSubmit} /> */}
      {/* {loading ? (
        <p>Loading...</p>
      ) : (
        <ScanResultsTable scanResultData={testData} />
      )} */}

      <ScanResultsTable resultsData={scanResults} />
    </div>
  );
};

export default SecurityDashboard;
