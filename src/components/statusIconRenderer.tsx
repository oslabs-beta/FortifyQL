import React, { useState, useEffect } from 'react';
import '../stylesheets/ag-theme-custom.scss';

interface IStatusIconsParams {
  data: {
    status: string;
  };
}

export const StatusIcons: React.FC<IStatusIconsParams> = ({ data }) => {
  const [imageSrc, setImageSrc] = useState<string>('');
  const [imageAlt, setImageAlt] = useState<string>('');

  useEffect(() => {
    if (data.status === 'Fail') {
      setImageSrc('../src/assets/cross.png');
      setImageAlt('red x indicating status failed');
    } else {
      setImageSrc('../src/assets/tick.png');
      setImageAlt('green check indicating status passed');
    }
  }, [data.status]);

  return (
    <span>
      <img src={imageSrc} alt={imageAlt} className='ag-status-icons' />
    </span>
  );
};
