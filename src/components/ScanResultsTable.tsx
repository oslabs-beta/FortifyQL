import { useState, useMemo, useCallback, useRef } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { ColDef, GridApi } from 'ag-grid-community';
import 'ag-grid-community/styles/ag-grid.css';
import 'ag-grid-community/styles/ag-theme-alpine.css';
import { ITestResult } from '../interfaces/results';
import ModalCellRenderer from './ModalCellRender';

interface IResultsTableProps {
  resultsData: ITestResult[];
  handleDisplayTestConfig: () => void;
}

const ScanResultsTable: React.FC<IResultsTableProps> = ({
  resultsData,
  handleDisplayTestConfig,
}) => {
  // console.log(resultsData);

  // State to store the AG Grid API
  const [gridApi, setGridApi] = useState<GridApi | null>(null);

  const gridStyle = useMemo(() => ({ height: '600px', width: '100%' }), []);

  // const [modalData, setModalData] = useState<string | null>(null);

  const colDefs: ColDef[] = [
    {
      field: 'status',
      maxWidth: 120,
    },
    {
      headerName: 'Test ID',
      field: 'id',
      maxWidth: 120,
    },
    { field: 'title', minWidth: 250 },
    {
      field: 'details',
      cellRenderer: 'modalCellRenderer',
      maxWidth: 100,
    },
    // { field: 'description' },
    // { field: 'severity', editable: true, maxWidth: 120 },
    { field: 'testDuration', maxWidth: 170 },
    { field: 'lastDetected' },
  ];

  // AG Grid Column Definitions
  const defaultColDef = useMemo(
    () => ({
      flex: 1,
      filter: true,
      sortable: true,
      resizable: true,
    }),
    [],
  );

  const components = useMemo(
    () => ({
      modalCellRenderer: ModalCellRenderer,
    }),
    [],
  );

  // Handles exporting data to CSV
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
    <div className='dashboard__container'>
      <h2 className='dashboard__headers'>Security Scan Results</h2>
      <div className='underline'></div>
      <div className='results-table-export__container'>
        <button
          id='dashboard-test-config__button'
          className='buttons'
          onClick={handleDisplayTestConfig}
        >
          Back to Test Configuration
        </button>
        <button
          id='dashboard-export-csv_button'
          className='buttons'
          onClick={handleExportCSV}
        >
          Export to CSV
        </button>
      </div>
      <div style={gridStyle} className='ag-theme-alpine'>
        <AgGridReact
          columnDefs={colDefs}
          rowData={resultsData}
          defaultColDef={defaultColDef}
          animateRows={true}
          onGridReady={(params) => setGridApi(params.api)}
          components={components}
        />
      </div>
    </div>
  );
};

export default ScanResultsTable;
