import React, { useState, useEffect } from 'react';

const ScanConfigForm: React.FC = () => {

  return (
    <form className='input_form'>
      <h1>FortifyQL</h1>
        <h2>Security Scan Dashboard</h2>
      <input id='textbox' type='text' placeholder='Enter GraphQL API Here...'></input>

        <div className='tests'> 
         <label className='text'><b>Injection Scan:&nbsp;</b>Allows an attacker to execute arbitrary SQL queries on a database, used to steal data, modify data, or even execute arbitrary code on the database server.</label>
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>

        <div className='tests'> 
        <label className='text'><b>Denial of Service (DoS) Scan:&nbsp;</b> Resource exhaustion via nested queries.</label>
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>


        <div className='tests'> 
        <label className='text'><b>Authoriation Configuration Scan:&nbsp;</b> Use administration email and brute force login credentials.</label>
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>


        <div className='tests'> 
        <label className='text'><b>Batching Scan:&nbsp;</b> Common for authentication vulnerabilities and bypassing rate limiting. A mutation to password reset, bypassing 2FA/OTP by batch sending tokens.</label>
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>


        <div className='tests'> 
        <label className='text'><b>Introspection Scan:&nbsp;</b> A query that performs an operation to pull the information from the backend of the application.</label>
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>

     <button>Submit</button>
    </form>
  )
};

export default ScanConfigForm;
