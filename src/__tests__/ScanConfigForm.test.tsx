import React from 'react';
import { render, fireEvent, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ScanConfigForm from '../components/ScanConfigForm';

describe('ScanConfigForm', () => {
  const mockOnScanSubmit = jest.fn();

  beforeEach(() => {
    render(<ScanConfigForm onScanSubmit={mockOnScanSubmit} />);
  });

  it('should allow entering an endpoint', () => {
    const input = screen.getByPlaceholderText('Enter GraphQL API URI Here');
    fireEvent.change(input, { target: { value: 'http://testendpoint.com' } });
    expect(input).toHaveValue('http://testendpoint.com');
  });

  it('should allow selecting tests', () => {
    const sqlCheckbox = screen.getByLabelText(/injection scan/i);
    fireEvent.click(sqlCheckbox);
    expect(sqlCheckbox).toBeChecked();
  });

  it('should submit form with endpoint and selected tests', () => {
    // Enter endpoint
    fireEvent.change(
      screen.getByPlaceholderText('Enter GraphQL API URI Here'),
      { target: { value: 'http://testendpoint.com' } },
    );

    // Select tests
    const sqlCheckbox = screen.getByLabelText(/injection scan/i);
    const dosCheckbox = screen.getByLabelText(
      /denial of service \(dos\) scan/i,
    );
    fireEvent.click(sqlCheckbox);
    fireEvent.click(dosCheckbox);

    // Submit form
    fireEvent.click(screen.getByText('Scan'));

    // Check if the mock function was called with correct arguments
    expect(mockOnScanSubmit).toHaveBeenCalledWith('http://testendpoint.com', [
      'SQL',
      'Circular',
    ]);
  });
});
