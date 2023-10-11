import React, { useState } from 'react';
import { Collapse } from 'react-collapse';

interface IAccordionProps {
  label: string;
  defaultIsOpen?: boolean;
  children: React.ReactNode;
}

const ModalAccordion: React.FC<IAccordionProps> = ({ children }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const toggleExpand = () => {
    setIsExpanded(!isExpanded);
  };

  return (
    <div className='accordion__container'>
      <button className='buttons' onClick={toggleExpand}>
        {isExpanded ? 'Hide Data' : 'Show Data'}
      </button>
      <Collapse isOpened={isExpanded}>{children}</Collapse>
    </div>
  );
};

export default ModalAccordion;
