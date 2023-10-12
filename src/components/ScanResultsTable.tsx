import { useState, useMemo } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { ColDef, GridApi, RowClassParams } from 'ag-grid-community';
import 'ag-grid-community/styles/ag-grid.css';
import 'ag-grid-community/styles/ag-theme-alpine.css';
import '../stylesheets/ag-theme-custom.scss';
import ModalCellRenderer from './ModalCellRender';
import { ITestResult } from '../interfaces/results';
import { StatusIcons } from './statusIconRenderer';

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

  const gridStyle = useMemo(() => ({ height: '600px', width: '100%' }), []);

  const colDefs: ColDef[] = [
    {
      field: 'status',
      maxWidth: 120,
      cellRenderer: StatusIcons,
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

  // AG Grid assign classes to rows based on pass/fail to color code
  const getRowClass = (params: RowClassParams) => {
    if (params.data.status === 'Fail') {
      return 'ag-row-fail';
    } else {
      return 'ag-row-pass';
    }
  };

  // AG Grid custom React components to display in table
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
        <button className='buttons' onClick={handleDisplayTestConfig}>
          Back to Test Configuration
        </button>
        <button className='buttons' onClick={handleExportCSV}>
          Export to CSV
        </button>
      </div>
      <div style={gridStyle} className='ag-theme-alpine' id='ag-results-table'>
        <AgGridReact
          columnDefs={colDefs}
          rowData={resultsData}
          getRowClass={getRowClass}
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
