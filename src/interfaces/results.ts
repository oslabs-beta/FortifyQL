export interface ITestResult {
  id: string;
  status: string;
  title: string;
  details: {
    query: string;
    response: string;
    description: string;
    solution?: string;
    link?: string;
  };
  severity: string;
  testDuration: string;
  lastDetected: string;
}
