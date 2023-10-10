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

const resultsData = [
  {
    id: 'Inj-2',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      'query { allFilms(after: "\'OR 1=1\'", before: "\'OR 1=1\'") { totalCount } }',
    severity: 'P1',
    testDuration: '91 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-3',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allFilms(after: \"' OR '1'='1\", before: \"' OR '1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '57 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-4',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allFilms(after: \"') OR ('1'='1\", before: \"') OR ('1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-5',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description: 'query { allFilms(after: "\'", before: "\'") { totalCount } }',
    severity: 'P1',
    testDuration: '33 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-6',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allFilms(after: "\';", before: "\';") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-7',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description: 'query { allFilms(after: "--", before: "--") { totalCount } }',
    severity: 'P1',
    testDuration: '32 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-8',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allFilms(after: "OR IF(1=1, SLEEP(5), 0)", before: "OR IF(1=1, SLEEP(5), 0)") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-9',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allFilms(after: "OR pg_sleep(5)", before: "OR pg_sleep(5)") { totalCount } }',
    severity: 'P1',
    testDuration: '55 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-10',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allFilms(after: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)", before: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)") { totalCount } }',
    severity: 'P1',
    testDuration: '38 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-11',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      'query { allPeople(after: "\'OR 1=1\'", before: "\'OR 1=1\'") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-12',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allPeople(after: \"' OR '1'='1\", before: \"' OR '1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '36 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-13',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allPeople(after: \"') OR ('1'='1\", before: \"') OR ('1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '31 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-14',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allPeople(after: "\'", before: "\'") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-15',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allPeople(after: "\';", before: "\';") { totalCount } }',
    severity: 'P1',
    testDuration: '29 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-16',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allPeople(after: "--", before: "--") { totalCount } }',
    severity: 'P1',
    testDuration: '37 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-17',
    status: 'Fail',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allPeople(after: "OR IF(1=1, SLEEP(5), 0)", before: "OR IF(1=1, SLEEP(5), 0)") { totalCount } }',
    severity: 'P1',
    testDuration: '32 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-18',
    status: 'Fail',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allPeople(after: "OR pg_sleep(5)", before: "OR pg_sleep(5)") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-19',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allPeople(after: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)", before: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)") { totalCount } }',
    severity: 'P1',
    testDuration: '37 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-20',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      'query { allPlanets(after: "\'OR 1=1\'", before: "\'OR 1=1\'") { totalCount } }',
    severity: 'P1',
    testDuration: '33 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-21',
    status: 'Fail',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allPlanets(after: \"' OR '1'='1\", before: \"' OR '1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '32 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-22',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allPlanets(after: \"') OR ('1'='1\", before: \"') OR ('1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '41 ms',
    lastDetected: '10:57:11 - 2023-10-09',
  },
  {
    id: 'Inj-23',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allPlanets(after: "\'", before: "\'") { totalCount } }',
    severity: 'P1',
    testDuration: '38 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-24',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allPlanets(after: "\';", before: "\';") { totalCount } }',
    severity: 'P1',
    testDuration: '36 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-25',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allPlanets(after: "--", before: "--") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-26',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allPlanets(after: "OR IF(1=1, SLEEP(5), 0)", before: "OR IF(1=1, SLEEP(5), 0)") { totalCount } }',
    severity: 'P1',
    testDuration: '30 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-27',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allPlanets(after: "OR pg_sleep(5)", before: "OR pg_sleep(5)") { totalCount } }',
    severity: 'P1',
    testDuration: '40 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-28',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allPlanets(after: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)", before: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)") { totalCount } }',
    severity: 'P1',
    testDuration: '29 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-29',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      'query { allSpecies(after: "\'OR 1=1\'", before: "\'OR 1=1\'") { totalCount } }',
    severity: 'P1',
    testDuration: '38 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-30',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allSpecies(after: \"' OR '1'='1\", before: \"' OR '1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '32 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-31',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allSpecies(after: \"') OR ('1'='1\", before: \"') OR ('1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-32',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allSpecies(after: "\'", before: "\'") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-33',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allSpecies(after: "\';", before: "\';") { totalCount } }',
    severity: 'P1',
    testDuration: '33 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-34',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allSpecies(after: "--", before: "--") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-35',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allSpecies(after: "OR IF(1=1, SLEEP(5), 0)", before: "OR IF(1=1, SLEEP(5), 0)") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-36',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allSpecies(after: "OR pg_sleep(5)", before: "OR pg_sleep(5)") { totalCount } }',
    severity: 'P1',
    testDuration: '33 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-37',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allSpecies(after: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)", before: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-38',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      'query { allStarships(after: "\'OR 1=1\'", before: "\'OR 1=1\'") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-39',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allStarships(after: \"' OR '1'='1\", before: \"' OR '1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '38 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-40',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allStarships(after: \"') OR ('1'='1\", before: \"') OR ('1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '28 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-41',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allStarships(after: "\'", before: "\'") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-42',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allStarships(after: "\';", before: "\';") { totalCount } }',
    severity: 'P1',
    testDuration: '32 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-43',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allStarships(after: "--", before: "--") { totalCount } }',
    severity: 'P1',
    testDuration: '46 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-44',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allStarships(after: "OR IF(1=1, SLEEP(5), 0)", before: "OR IF(1=1, SLEEP(5), 0)") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-45',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allStarships(after: "OR pg_sleep(5)", before: "OR pg_sleep(5)") { totalCount } }',
    severity: 'P1',
    testDuration: '31 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-46',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allStarships(after: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)", before: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-47',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      'query { allVehicles(after: "\'OR 1=1\'", before: "\'OR 1=1\'") { totalCount } }',
    severity: 'P1',
    testDuration: '38 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-48',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allVehicles(after: \"' OR '1'='1\", before: \"' OR '1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '36 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-49',
    status: 'Pass',
    title: 'Boolean Based SQL Injection',
    description:
      "query { allVehicles(after: \"') OR ('1'='1\", before: \"') OR ('1'='1\") { totalCount } }",
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-50',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allVehicles(after: "\'", before: "\'") { totalCount } }',
    severity: 'P1',
    testDuration: '36 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-51',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allVehicles(after: "\';", before: "\';") { totalCount } }',
    severity: 'P1',
    testDuration: '33 ms',
    lastDetected: '10:57:12 - 2023-10-09',
  },
  {
    id: 'Inj-52',
    status: 'Pass',
    title: 'Error Based SQL Injection',
    description:
      'query { allVehicles(after: "--", before: "--") { totalCount } }',
    severity: 'P1',
    testDuration: '34 ms',
    lastDetected: '10:57:13 - 2023-10-09',
  },
  {
    id: 'Inj-53',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allVehicles(after: "OR IF(1=1, SLEEP(5), 0)", before: "OR IF(1=1, SLEEP(5), 0)") { totalCount } }',
    severity: 'P1',
    testDuration: '35 ms',
    lastDetected: '10:57:13 - 2023-10-09',
  },
  {
    id: 'Inj-54',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allVehicles(after: "OR pg_sleep(5)", before: "OR pg_sleep(5)") { totalCount } }',
    severity: 'P1',
    testDuration: '37 ms',
    lastDetected: '10:57:13 - 2023-10-09',
  },
  {
    id: 'Inj-55',
    status: 'Pass',
    title: 'Time-Based Blind SQL Injection',
    description:
      'query { allVehicles(after: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)", before: "OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)") { totalCount } }',
    severity: 'P1',
    testDuration: '31 ms',
    lastDetected: '10:57:13 - 2023-10-09',
  },
];

const ScanResultsTable: React.FC<IResultsTableProps> = ({
  // resultsData,
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
    <div className='results-table__container'>
<<<<<<< HEAD
      <div
        className='ag-theme-alpine'
        style={{ height: '100%', width: '100%' }}
      >
        <h2 id='results-table__header'>Security Scan Results</h2>
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
=======
      <h2 id='results-table__header'>Security Scan Results</h2>
      <div className='results-table-export__container'>
        <button
          id='dashboard-test-config__button'
          onClick={handleDisplayTestConfig}
        >
          Back to Test Configuration
        </button>
        <button id='dashboard-export-csv_button' onClick={handleExportCSV}>
          Export to CSV
        </button>
      </div>
      <div style={gridStyle} className='ag-theme-alpine'>
>>>>>>> 8b35d28cca9361e8fb583e04606c200436fe16c8
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
