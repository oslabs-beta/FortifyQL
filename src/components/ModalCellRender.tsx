import React, { useEffect, useState } from 'react';
import Modal from 'react-modal';
import { ITestResult } from '../interfaces/results';
import { prettifyJson, prettyPrintGraphQL } from '../utils/format';
import ModalAccordion from './ModalAccordion';

interface IModalCellRendererProps {
  isModalOpen: boolean;
  setIsModalOpen: React.Dispatch<React.SetStateAction<boolean>>;
  closeModal: () => void;
  data: ITestResult;
}

Modal.setAppElement('#root');

const customStyles = {
  overlay: {
    // backgroundColor: 'rgba(208, 204, 204)',
  },
  content: {
    backgroundColor: 'rgba(208, 204, 204, 0)',
    top: '5%',
    left: 'auto',
    right: 'auto',
    bottom: 'auto',
    border: 0,
    // marginRight: '-50%',
    // transform: 'translate(-50%, -50%)',
  },
};

const ModalCellRenderer: React.FC<IModalCellRendererProps> = ({ data }) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalData, setModalData] = useState(data);

  const openModal = () => {
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
  };

  useEffect(() => {
    setModalData(data);
  }, [data]);

  return (
    <div className='outer-modal__container'>
      <button onClick={openModal}>View</button>
      {isModalOpen && (
        <Modal
          isOpen={isModalOpen}
          onRequestClose={closeModal}
          style={customStyles}
        >
          <div className='dashboard__container'>
            <span id='modal-close__button'>
              <button className='buttons' onClick={closeModal}>
                Close
              </button>
            </span>
            <h2 id='modal__header' className='dashboard__headers'>
              {modalData.title}
            </h2>
            <div className='underline' id='modal-underline'></div>
            <div className='modal-details__container'>
              <h3>Description:</h3>
              <p>{modalData.details.description}</p>
              <h3>Query: </h3>
              <ModalAccordion label='Query'>
                <pre>
                  <code>{prettyPrintGraphQL(modalData.details.query)}</code>
                </pre>
              </ModalAccordion>
              <h3>Response:</h3>
              <ModalAccordion label='Response'>
                <pre>
                  <code>{prettifyJson(modalData.details.response)}</code>
                </pre>
              </ModalAccordion>
              <h3>Solution:</h3>
              <p>{modalData.details.solution}</p>
              <a href={modalData.details.link}>{modalData.details.link}</a>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

export default ModalCellRenderer;
