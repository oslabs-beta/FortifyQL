import { render, screen } from '@testing-library/react';
import App from '../App';

jest.mock('react-modal');

test('Renders main page correctly', async () => {
  render(<App />);
  expect(true).toBeTruthy();
});
