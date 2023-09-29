import React, { useState, FormEvent } from 'react';

interface IConfigFormProps {
  onScanSubmit: (endpoint: string, tests: string[]) => void;
};

const ScanConfigForm: React.FC<IConfigFormProps> = (props) => {
  // Destructuring props
  const { onScanSubmit } = props;

  // Sets the state of textbox input
  const [endpoint, setEndpoint] = useState<string>('');

  // Function that handles and updates the textbox state
  const handleEndpoint = (e: React.BaseSyntheticEvent) => {
    setEndpoint(e.target.value);
  };

  // Sets the state of the selected tests array
  const [selectedTests, setSelectedTests] = useState<string[]>([]);

  // Function that evaluates the 'value' and 'checked' properties on the event object and updates the state of the selectedTests array accordingly
  const handleSelectedTests = (e: React.ChangeEvent<HTMLInputElement>) => {
    const testType = e.target.value;
    if (e.target.checked === true) {
      setSelectedTests([...selectedTests, testType]);
    } else if (e.target.checked === false) {
      setSelectedTests(selectedTests.filter((test) => test !== testType));
    }
  };

  // Submits the form data
  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    onScanSubmit(endpoint, selectedTests);
  };

  return (
    <div className='container'>
      <form className='input_form' onSubmit={handleSubmit}>
        <h1>FortifyQL</h1>
        <h2>Security Scan Dashboard</h2>
        <input
          id='textbox'
          type='text'
          placeholder='Enter GraphQL API URI here'
          onChange={handleEndpoint}
        ></input>

        <div className='tests'>
          <label className='text'>
            <b>Injection Scan:&nbsp;</b>Allows an attacker to execute arbitrary
            SQL queries on a database, used to steal data, modify data, or even
            execute arbitrary code on the database server.
          </label>
          <label className='switch'>
            <input
              type='checkbox'
              value='injection-scan'
              onChange={handleSelectedTests}
            />
            <span className='slider' />
          </label>
        </div>

        <div className='tests'>
          <label className='text'>
            <b>Denial of Service (DoS) Scan:&nbsp;</b> Resource exhaustion via
            nested queries.
          </label>
          <label className='switch'>
            <input
              type='checkbox'
              value='dos-scan'
              onChange={handleSelectedTests}
            />
            <span className='slider' />
          </label>
        </div>

        <div className='tests'>
          <label className='text'>
            <b>Authorization Configuration Scan:&nbsp;</b> Use administration
            email and brute force login credentials.
          </label>
          <label className='switch'>
            <input
              type='checkbox'
              value='authorization-scan'
              onChange={handleSelectedTests}
            />
            <span className='slider' />
          </label>
        </div>

        <div className='tests'>
          <label className='text'>
            <b>Batching Scan:&nbsp;</b> Common for authentication
            vulnerabilities and bypassing rate limiting. A mutation to password
            reset, bypassing 2FA/OTP by batch sending tokens.
          </label>
          <label className='switch'>
            <input
              type='checkbox'
              value='batching-scan'
              onChange={handleSelectedTests}
            />
            <span className='slider' />
          </label>
        </div>

        <div className='tests'>
          <label className='text'>
            <b>Introspection Scan:&nbsp;</b> A query that performs an operation
            to pull the information from the backend of the application.
          </label>
          <label className='switch'>
            <input
              type='checkbox'
              value='introspection-scan'
              onChange={handleSelectedTests}
            />
            <span className='slider' />
          </label>
        </div>

        {/* <button id='select_all_button' onChange={handleSelectAllButton}>Select All Tests</button> */}
        <button id='submit_button'>Submit</button>
      </form>
    </div>
  );
};

export default ScanConfigForm;
