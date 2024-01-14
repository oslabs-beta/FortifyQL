/**
 * ************************************
 *
 * @module  Checkbox.tsx
 * @author  MADR Productions - MK
 * @date    01-13-24
 * @description This file defines a React functional component called Checkbox, which represents a checkbox element with associated properties like value, label, and description.
 *
 * ************************************
 */
import React from 'react';

interface ICheckboxProps {
  value: string;
  label: string;
  description: string;
  isChecked: boolean;
  onChange: (value: string, isChecked: boolean) => void;
}

const Checkbox: React.FC<ICheckboxProps> = (props) => {

  const { value, label, description, isChecked, onChange } = props;

  const handleCheckboxChange = () => {
    onChange(value, !isChecked);
  }

  return (
    <div className='tests'>
      <label className='switch'>
        <input type='checkbox' value={value} checked={isChecked} onChange={handleCheckboxChange}/>
        <span className='slider'/>
      </label>
      <label className='text'>
        <b>{label}:&nbsp;</b>{description}
      </label>
    </div>
  );
};

export default Checkbox;