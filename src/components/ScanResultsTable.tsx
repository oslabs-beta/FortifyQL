import { useMemo } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { ColDef } from 'ag-grid-community';
import 'ag-grid-community/styles/ag-grid.css';
import 'ag-grid-community/styles/ag-theme-alpine.css';
import { ITestResult } from '../interfaces/results';

interface IResultsTableProps {
  resultsData: ITestResult[];
}

const ScanResultsTable: React.FC<IResultsTableProps> = ({
  resultsData: results,
}) => {
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

  return (
    <div className='ag-theme-alpine' style={{ height: '400px', width: '100%' }}>
      <AgGridReact
        columnDefs={colDefs}
        rowData={results}
        defaultColDef={defaultColDef}
        domLayout='autoHeight'
      />
    </div>
  );
};

export default ScanResultsTable;
