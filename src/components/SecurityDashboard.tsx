import React, { useState } from 'react';
import ScanConfigForm from './ScanConfigForm';
import ScanResultsTable from './ScanResultsTable';
import testData from './scanTestData.json';
import { ITestResult } from '../interfaces/results';

const SecurityDashboard: React.FC = () => {
  const [scanResults, setScanResults] = useState<ITestResult[]>(testData);
  // Test Result Table loading state
  const [loading, setLoading] = useState(false);
  // Form visibility state
  const [showConfigForm, setShowConfigForm] = useState(true);

  const handleScanSubmit = async (
    endpoint: string,
    selectedTests: string[],
  ) => {
    setLoading(true);

    try {
      const response = await fetch(
        `MIDDLEWARE_ENDPOINT?endpoint=${endpoint}&tests=${selectedTests.join(
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
      setShowConfigForm(false); // Hide the config form after submitting
    }
  };

  return (
    <div className='dashboard__container'>
      <h2 className='dashboard__header'>Security Dashboard</h2>
      {showConfigForm ? (
        <ScanConfigForm />
      ) : (
        <div>
          {/* {loading ? (
            <p>Loading...</p>
            ) : (
              <ScanResultsTable resultsData={scanResults} />
            )} */}
        </div>
      )}
      <ScanResultsTable resultsData={scanResults} />
    </div>
  );
};

export default SecurityDashboard;
