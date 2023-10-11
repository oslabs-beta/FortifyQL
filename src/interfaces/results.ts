export interface ITestResult {
  id: number;
  status: string;
  title: string;
  details: string;
  description: string;
  severity: string;
  testDuration: string;
  lastDetected: string;
}
