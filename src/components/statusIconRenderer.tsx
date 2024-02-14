import React from 'react';
import '../stylesheets/ag-theme-custom.scss';

interface InitParams {
  data: {
    status: string;
  };
}

export class StatusIcons {

  eGui: HTMLElement | null = null
  init(params: InitParams) {
    const element = document.createElement('span');
    const imageElement = document.createElement('img');
    if (params.data.status === 'Fail') {
      imageElement.src = '../src/assets/cross.png';
      imageElement.alt = 'red x indicating status failed';
      imageElement.className = 'ag-status-icons';
    } else {
      imageElement.src = '../src/assets/tick.png';
      imageElement.alt = 'green check indicating status passed';
      imageElement.className = 'ag-status-icons';
    }
    element.appendChild(imageElement);
    this.eGui = element;
  }

  getGui(): HTMLElement | null {
    return this.eGui;
  }
}