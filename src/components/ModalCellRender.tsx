import React, { useEffect, useState } from 'react';
import Modal from 'react-modal';
import { ITestResult } from '../interfaces/results';

interface ModalCellRendererProps {
  isModalOpen: boolean;
  setIsModalOpen: React.Dispatch<React.SetStateAction<boolean>>;
  closeModal: () => void;
  data: ITestResult;
}

Modal.setAppElement('#root');

const customStyles = {
  overlay: {
    backgroundColor: '#ede7e7',
  },
  content: {
    top: '50%',
    left: '50%',
    right: 'auto',
    bottom: 'auto',
    marginRight: '-50%',
    transform: 'translate(-50%, -50%)',
  },
};

const ModalCellRenderer: React.FC<ModalCellRendererProps> = ({ data }) => {
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
    <div className='details-modal__container'>
      <button onClick={openModal}>View</button>
      {isModalOpen && (
        <Modal
          isOpen={isModalOpen}
          onRequestClose={closeModal}
          style={customStyles}
        >
          <button onClick={closeModal}>Close</button>
          <h3>{modalData.title}</h3>
          <p>Description: {modalData.details.description}</p>
          <p>Query: </p>
          <div>
            <pre>
              <code>{modalData.details.query}</code>
            </pre>
          </div>
          <p>Response:{JSON.stringify(modalData.details.response)}</p>
          <div>
            <pre>
              {/* <code>{JSON.stringify(modalData.details.response)}</code> */}
            </pre>
          </div>
          <p>Solution: {modalData.details.solution}</p>
          <a href={modalData.details.link}>{modalData.details.link}</a>
        </Modal>
      )}
    </div>
  );
};

export default ModalCellRenderer;
