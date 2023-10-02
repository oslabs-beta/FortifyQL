import { useState, useMemo } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { ColDef, GridApi } from 'ag-grid-community';
import 'ag-grid-community/styles/ag-grid.css';
import 'ag-grid-community/styles/ag-theme-alpine.css';
import { ITestResult } from '../interfaces/results';

interface IResultsTableProps {
  resultsData: ITestResult[];
  handleDisplayTestConfig: () => void;
}

const ScanResultsTable: React.FC<IResultsTableProps> = ({
  resultsData,
  handleDisplayTestConfig,
}) => {
  // State to store the AG Grid API
  const [gridApi, setGridApi] = useState<GridApi | null>(null);

  const colDefs: ColDef[] = [
    { headerName: 'Test ID', field: 'id' },
    { field: 'status', headerTooltip: 'Pending / Pass / Fail' },
    { field: 'description' },
    { field: 'severity', editable: true },
    { field: 'testDuration' },
    { field: 'lastDetected' },
  ];

  // AG Grid Column Definitions
  const defaultColDef = useMemo(
    () => ({
      sortable: true,
      filter: true,
      resizeable: true,
      flex: 1,
    }),
    [],
  );

  // Function to handle exporting data to CSV
  const handleExportCSV = () => {
    if (gridApi) {
      const params = {
        fileName: 'test-results.csv',
        columnSeparator: ',',
      };
      gridApi.exportDataAsCsv(params);
    }
  };

  return (
    <div className='results-table__container'>
      <div
        className='ag-theme-alpine'
        style={{ height: '100%', width: '100%' }}
      >
        <h2 className='results-table__header'>Security Scan Results</h2>
        <div className='results-table-export__container'>
          <button
            className='dashboard-test-config__button'
            onClick={handleDisplayTestConfig}
          >
            Back to Test Configuration
          </button>
          <button onClick={handleExportCSV}>Export to CSV</button>
        </div>
        <AgGridReact
          columnDefs={colDefs}
          rowData={resultsData}
          defaultColDef={defaultColDef}
          domLayout='autoHeight'
          onGridReady={(params) => setGridApi(params.api)}
        />
      </div>
    </div>
  );
};

export default ScanResultsTable;
