import React from 'react';
import '@testing-library/jest-dom';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SecurityDashboard from '../components/SecurityDashboard';

jest.mock('react-modal', () => ({
  ...jest.requireActual('react-modal'),
  setAppElement: () => {},
}));

global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve([]),
  }),
);

beforeEach(() => {
  fetch.mockClear();
});

test('Dashboard initally renders config form and not result or loading screen', () => {
  render(<SecurityDashboard />);
  const configForm = screen.getByPlaceholderText('Enter GraphQL API URI Here');
  const loader = screen.queryByTestId('table-loader');

  expect(configForm).toBeInTheDocument();
  expect(loader).toBeNull();
});

test('Results table shown after loading screen when a submission is made', async () => {
  render(<SecurityDashboard />);
  const url = 'www.fakeurl.com';

  const urlInput = screen.getByPlaceholderText('Enter GraphQL API URI Here');
  await userEvent.type(urlInput, url);
  const scanButton = screen.getByRole('button', { name: 'Scan' });
  await userEvent.click(scanButton);

  await waitFor(() => expect(screen.queryByText(/Scanning.../i)).not.toBeInTheDocument());
  expect(screen.getByText(/Security Scan Results/i)).toBeInTheDocument()
});
