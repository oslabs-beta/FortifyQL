/**
 * ************************************
 *
 * @module  ScanConfigForm.tsx
 * @author  MADR Productions - MK
 * @date    01-13-24
 * @description This component represents a form for configuring a security scan. It includes input fields for a GraphQL API URI, checkboxes for different scan types, and buttons to submit the form and select all available scan types. The component manages the state of selected tests and the URI textbox.
 *
 * ************************************
 */
import React, { useState, FormEvent } from 'react';
import Checkbox from './Checkbox';

interface IConfigFormProps {
  onScanSubmit: (endpoint: string, tests: string[]) => void;
}

const ScanConfigForm: React.FC<IConfigFormProps> = (props) => {
  const { onScanSubmit } = props;

  // Sets the state of textbox input
  const [endpoint, setEndpoint] = useState<string>('');

  // Sets the state of the selected tests array
  const [selectedTests, setSelectedTests] = useState<string[]>([]);
  
  // Function that manages the textbox state
  const handleEndpoint = (e: React.BaseSyntheticEvent) => {
    setEndpoint(e.target.value);
  };

  // Function that manages the checkbox state
  const handleCheckboxChange = (testType: string, isChecked: boolean) => {
    setSelectedTests((prevSelectedTests) => {
      return isChecked
        ? [...prevSelectedTests, testType]
        : prevSelectedTests.filter((test) => test !== testType);
    });
  };

  // Button that submits the form data
  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    onScanSubmit(endpoint, selectedTests);
  };

  // Button that updates the state of selectedTests to include all tests
  const selectAllTests = (e: React.BaseSyntheticEvent) => {
    e.preventDefault();
    const allTests = ['Batching', 'Circular', 'SQL', 'Verbose'];
    setSelectedTests(allTests);
  };

  return (
    <div className='dashboard__container'>
      <form className='input_form' onSubmit={handleSubmit}>
        <h2 className='dashboard__headers'>Security Scan Configuration</h2>
        <div className='underline'></div>
        <input
          id='textbox'
          type='text'
          placeholder='Enter GraphQL API URI Here'
          required
          onChange={handleEndpoint}>
        </input>

        <Checkbox value='Batching' label='Batching Scan' 
          onChange={handleCheckboxChange}
          isChecked={selectedTests.includes('Batching')}
          description='Common for authentication vulnerabilities
          and bypassing rate limiting. A mutation to password reset, bypassing
          2FA/OTP by batch sending tokens.'/>

        <Checkbox value='Circular' label='Denial of Service (DoS) Scan' 
          onChange={handleCheckboxChange}
          isChecked={selectedTests.includes('Circular')}
          description='Resource exhaustion via nested circular queries.'/>

        <Checkbox value='SQL' label='Injection Scan'
          onChange={handleCheckboxChange}
          isChecked={selectedTests.includes('SQL')}
          description='Allows an attacker to execute arbitrary SQL queries on a database, used to steal data, modify data, or even execute arbitrary code on the database server.'/>

        <Checkbox value='Verbose' label='Verbose Error Scan' 
          onChange={handleCheckboxChange}
          isChecked={selectedTests.includes('Verbose')}
          description='A query that analyzes error response
          for verbose error messages revealing system information.'/>

        <button id='select_all_button' className='buttons' 
          onClick={selectAllTests}>Select All</button>
        <button id='submit_button' className='buttons'>Scan</button>
      </form>
    </div>
  );
};

export default ScanConfigForm;