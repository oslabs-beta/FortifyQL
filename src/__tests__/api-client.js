import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ScanConfigForm from '../components/ScanConfigForm';

test('Configuration form sends a request to the correct endpoint', async () => {
  const onScanSubmit = jest.fn();
  render(<ScanConfigForm onScanSubmit={onScanSubmit} />);

  const url = 'www.fakeurl.com';

  const urlInput = screen.getByPlaceholderText('Enter GraphQL API URI Here');
  await userEvent.type(urlInput, url);

  const scanButton = screen.getByRole('button', { name: 'Scan' });
  await userEvent.click(scanButton);

  expect(onScanSubmit).toHaveBeenCalledTimes(1);
  expect(onScanSubmit).toHaveBeenCalledWith(url, []);
});

test('If no url is provided, prompts user to fill the field and does not send request', async () => {
  const onScanSubmit = jest.fn();
  render(<ScanConfigForm onScanSubmit={onScanSubmit} />);

  const selectAllButton = screen.getByRole('button', { name: 'Select All' });
  await userEvent.click(selectAllButton);

  const scanButton = screen.getByRole('button', { name: 'Scan' });
  await userEvent.click(scanButton);

  expect(onScanSubmit).not.toHaveBeenCalled();
});

test('Select All buttons will properly check all test options', async () => {
  const onScanSubmit = jest.fn();
  render(<ScanConfigForm onScanSubmit={onScanSubmit} />);

  const url = 'www.fakeurl.com';

  const urlInput = screen.getByPlaceholderText('Enter GraphQL API URI Here');
  await userEvent.type(urlInput, url);

  const selectAllButton = screen.getByRole('button', { name: 'Select All' });
  await userEvent.click(selectAllButton);

  const scanButton = screen.getByRole('button', { name: 'Scan' });
  await userEvent.click(scanButton);

  expect(onScanSubmit).toHaveBeenCalledTimes(1);
  expect(onScanSubmit).toHaveBeenCalledWith(url, [
    'Batching',
    'Circular',
    'SQL',
    'Verbose',
  ]);
});
