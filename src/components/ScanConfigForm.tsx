import React, { useState, useEffect } from 'react';
import style from '../styles.css?inline';

const ScanConfigForm: React.FC = () => {

  return (
    <form className='input_form'>
      <input id='textbox' type='text' placeholder='Enter GraphQL API Here...'></input>

        <div className='tests'> 
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>

        <div className='tests'> 
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>


        <div className='tests'> 
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>


        <div className='tests'> 
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>


        <div className='tests'> 
         <label className='switch'>
          <input type='checkbox'/>
           <span className='slider'/>
         </label>
        </div>

      <button>Submit</button>
    </form>
 
  )
};

// const styles = {
//   display: 'flex',
//   flexDirection: 'center',
//   width: '150%',
//   height: '40px',

// }

export default ScanConfigForm;
