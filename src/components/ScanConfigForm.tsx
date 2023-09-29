import React, { useState, useEffect, FormEvent } from 'react';

interface ConfigFormProps {
  onScanSubmit: (endpoint: string, tests: string[]) => void;
}

const ScanConfigForm: React.FC<ConfigFormProps> = (props) => {
  // handleScanSubmit function
  const { onScanSubmit } = props;
  // Sets the state of textbox input
  const [endpoint, setEndpoint] = useState<string>('');

  // Function that handles and updates the textbox state
  const handleEndpoint = (e: React.BaseSyntheticEvent) => {
    console.log(e.target.value);
    setEndpoint(e.target.value);
  };

  // Sets the state of the selected tests array
  const [selectedTests, setSelectedTests] = useState<string[]>([]);

  // Renders and console logs the updated selectedTests array immediately
  useEffect(() => {
    console.log(selectedTests);
  }, [selectedTests]);

  // Function that evaluates the 'value' and 'checked' values on the event and updates the state of the selectedTests array accordingly depending on if 'checked' is true or false
  const handleSelectedTests = (e: React.ChangeEvent<HTMLInputElement>) => {
    const testType = e.target.value;

    if (e.target.checked === true) {
      setSelectedTests([...selectedTests, testType]);
    } else if (e.target.checked === false) {
      setSelectedTests(selectedTests.filter((test) => test !== testType));
    }
    console.log(selectedTests);
  };

  // const handleSelectAllButton = () => {
  //   console.log('clicked');
  // }

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    onScanSubmit(endpoint, selectedTests);
  };

  return (
    <div className='container'>
      <form className='input_form' onSubmit={handleSubmit}>
        <h2 id='dashboardHeader'>Security Scan Configuration</h2>
        <div className='underline'></div>
        <input
          id='textbox'
          type='text'
          placeholder='Enter GraphQL API URI Here'
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
              value='DoS-scan'
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
        <button id='submit_button'>Scan</button>
      </form>
    </div>
  );
};

export default ScanConfigForm;
