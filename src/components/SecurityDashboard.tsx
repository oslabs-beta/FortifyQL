import React, { useState } from 'react';
import ScanConfigForm from './ScanConfigForm';
import ScanResultsTable from './ScanResultsTable';
// import testData from './scanTestData.json';
import { ITestResult } from '../interfaces/results';

const SecurityDashboard: React.FC = () => {
  const [scanResults, setScanResults] = useState<ITestResult[]>([]);
  // Test Result Table loading state
  const [loading, setLoading] = useState<boolean>(false);
  // Form visibility state
  const [showConfigForm, setShowConfigForm] = useState<boolean>(true);

  const handleScanSubmit = async (
    endpoint: string,
    selectedTests: string[],
  ) => {
    setLoading(true);

    try {
      const requestBody = JSON.stringify({
        API: endpoint,
        tests: selectedTests,
      });

      const response = await fetch('/api/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: requestBody,
      });

      if (!response.ok) {
        throw new Error('test api response error occurred');
      }

      const data = await response.json();

      setScanResults(data); // Update scanResults with the received data
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
      setShowConfigForm(false); // Hide the config form after submitting
    }
  };

  const handleDisplayTestConfig = () => {
    setShowConfigForm(true);
  };

  return (
    <div className='dashboard__container'>
      <h2 className='dashboard__header'>Security Dashboard</h2>

      {showConfigForm ? (
        <ScanConfigForm onScanSubmit={handleScanSubmit} />
      ) : (
        <div>
          {loading ? (
            <p>Loading...</p>
          ) : (
            <ScanResultsTable
              resultsData={scanResults}
              handleDisplayTestConfig={handleDisplayTestConfig}
            />
          )}
        </div>
      )}
    </div>
  );
};

export default SecurityDashboard;
